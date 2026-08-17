package net.xzh.authserver.remote;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.AuthServerProperties;

/**
 * 服务令牌供给 (M2M client_credentials).
 * <p>
 * 认证中心调用资源中心 (iam-resource-service) 接口时, 以 client_credentials 换取服务凭证令牌,
 * 进程内按令牌有效期缓存 TTL, 供 {@link RemoteRoleService} / {@link InternalUserDataClient}
 * 等远程调用方复用。两类服务凭证 (各独立缓存):
 * <ul>
 *   <li><b>门户服务凭证</b>: {@code resource-server} 客户端签发 (→ 资源中心注入
 *       PORTAL_SERVICE_TOKEN), 供 {@code /api/internal/**} 只读角色内省;</li>
 *   <li><b>管理 M2M 凭证</b>: {@code admin-m2m} 客户端签发 (→ 资源中心按 client_id 白名单
 *       注入 ADMIN_SERVICE_TOKEN), 供 {@code /api/admin/**} 管理写 (如删除用户联动清理)。</li>
 * </ul>
 */
@Slf4j
@Component
public class ServiceTokenProvider {

    private static final long TOKEN_SAFE_MARGIN_SECONDS = 60;

    private final AuthServerProperties properties;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** 缓存的 service token (带过期时间) */
    private volatile CacheEntry<String> tokenCache;

    /** 缓存的管理 M2M 服务令牌 (带过期时间) */
    private volatile CacheEntry<String> adminTokenCache;

    public ServiceTokenProvider(AuthServerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * 获取门户服务凭证令牌, 进程内缓存.
     *
     * @throws IllegalStateException 令牌端点不可达或响应异常
     */
    public String getToken() {
        return getCached(() -> tokenCache, entry -> tokenCache = entry,
                () -> acquire(properties.getServiceTokenClientId(), properties.getServiceTokenClientSecret()));
    }

    /**
     * 获取管理 M2M 服务凭证令牌 (admin-m2m 客户端), 进程内缓存.
     *
     * @throws IllegalStateException 令牌端点不可达或响应异常
     */
    public String getAdminToken() {
        return getCached(() -> adminTokenCache, entry -> adminTokenCache = entry,
                () -> acquire(properties.getAdminServiceTokenClientId(), properties.getAdminServiceTokenClientSecret()));
    }

    /** 判定缓存失效 (如目标端返回 401) 后调用, 下次获取将强制刷新 */
    public void invalidate() {
        tokenCache = null;
    }

    /** 管理 M2M 凭证缓存失效 (如目标端返回 401), 下次获取将强制刷新 */
    public void invalidateAdminToken() {
        adminTokenCache = null;
    }

    private String getCached(java.util.function.Supplier<CacheEntry<String>> cacheRef,
                             java.util.function.Consumer<CacheEntry<String>> cacheWrite,
                             java.util.function.Supplier<TokenResponse> acquireFn) {
        CacheEntry<String> cached = cacheRef.get();
        if (cached != null && !cached.expired()) {
            return cached.value;
        }
        synchronized (this) {
            cached = cacheRef.get();
            if (cached != null && !cached.expired()) {
                return cached.value;
            }
            TokenResponse tr = acquireFn.get();
            CacheEntry<String> entry = new CacheEntry<>(tr.token(),
                    System.currentTimeMillis() + Math.max(tr.expiresInSeconds() - TOKEN_SAFE_MARGIN_SECONDS, 30) * 1000);
            cacheWrite.accept(entry);
            return tr.token();
        }
    }

    private TokenResponse acquire(String clientId, String clientSecret) {
        String basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret)
                        .getBytes(StandardCharsets.UTF_8));
        String form = "grant_type=client_credentials&scope=read";
        HttpRequest request = HttpRequest.newBuilder(URI.create(properties.getServiceTokenEndpoint()))
                .timeout(Duration.ofSeconds(5))
                .header("Authorization", "Basic " + basic)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        try {
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("服务令牌接口返回 HTTP " + resp.statusCode());
            }
            JsonNode root = objectMapper.readTree(resp.body());
            String token = root.path("access_token").asText();
            if (token.isBlank()) {
                throw new IllegalStateException("服务令牌响应缺少 access_token");
            }
            return new TokenResponse(token, root.path("expires_in").asLong(3600));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("获取服务令牌失败: " + e.getMessage(), e);
        }
    }

    private record TokenResponse(String token, long expiresInSeconds) {
    }

    private record CacheEntry<T>(T value, long expireAt) {
        boolean expired() {
            return System.currentTimeMillis() > expireAt;
        }
    }
}