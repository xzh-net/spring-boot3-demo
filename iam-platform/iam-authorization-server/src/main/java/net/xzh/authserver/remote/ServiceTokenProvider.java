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
 * 认证中心调用资源中心 (iam-resource-service) 内部接口时, 以
 * {@code resource-server} 客户端 client_credentials 换取 PORTAL_SERVICE_TOKEN 门户服务凭证令牌,
 * 进程内按令牌有效期缓存 TTL, 供 {@link RemoteRoleService} /
 * {@link InternalUserDataClient} 等远程调用方复用。
 * </p>
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

    public ServiceTokenProvider(AuthServerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * 获取服务令牌, 进程内缓存.
     *
     * @throws IllegalStateException 令牌端点不可达或响应异常
     */
    public String getToken() {
        CacheEntry<String> cached = tokenCache;
        if (cached != null && !cached.expired()) {
            return cached.value;
        }
        synchronized (this) {
            cached = tokenCache;
            if (cached != null && !cached.expired()) {
                return cached.value;
            }
            TokenResponse tr = acquire();
            tokenCache = new CacheEntry<>(tr.token(),
                    System.currentTimeMillis() + Math.max(tr.expiresInSeconds() - TOKEN_SAFE_MARGIN_SECONDS, 30) * 1000);
            return tr.token();
        }
    }

    /** 判定缓存失效 (如目标端返回 401) 后调用, 下次获取将强制刷新 */
    public void invalidate() {
        tokenCache = null;
    }

    private TokenResponse acquire() {
        String basic = Base64.getEncoder().encodeToString(
                (properties.getServiceTokenClientId() + ":" + properties.getServiceTokenClientSecret())
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