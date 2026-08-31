package net.xzh.iam.identity.remote;

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
import net.xzh.iam.identity.config.IdentityProperties;

/**
 * 管理 M2M 服务令牌供给 (client_credentials, admin-m2m).
 * <p>
 * 身份管理面调用下游 (认证中心内部供给 API / 权限中心管理域) 的唯一机器身份。
 * 权限中心按 client_id 白名单内省注入 ADMIN_SERVICE_TOKEN (管理服务凭证),
 * 认证中心内部 API 按 internal-identity-client-ids 白名单放行。
 * 进程内按令牌有效期缓存, 401 时可强制刷新自愈。
 */
@Slf4j
@Component
public class ManagementTokenProvider {

    private static final long TOKEN_SAFE_MARGIN_SECONDS = 60;

    private final IdentityProperties properties;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private volatile CacheEntry<String> tokenCache;

    public ManagementTokenProvider(IdentityProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * 获取管理 M2M 服务令牌, 进程内缓存.
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
            String basic = Base64.getEncoder().encodeToString(
                    (properties.getM2mClientId() + ":" + properties.getM2mClientSecret())
                            .getBytes(StandardCharsets.UTF_8));
            HttpRequest request = HttpRequest.newBuilder(URI.create(properties.getServiceTokenEndpoint()))
                    .timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Basic " + basic)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope=read"))
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
                long expiresInSeconds = root.path("expires_in").asLong(3600);
                tokenCache = new CacheEntry<>(token,
                        System.currentTimeMillis() + Math.max(expiresInSeconds - TOKEN_SAFE_MARGIN_SECONDS, 30) * 1000);
                return token;
            } catch (IllegalStateException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("获取服务令牌失败: " + e.getMessage(), e);
            }
        }
    }

    /** 令牌失效 (下游 401) 后强制刷新 */
    public void invalidate() {
        tokenCache = null;
    }

    private record CacheEntry<T>(T value, long expireAt) {
        boolean expired() {
            return System.currentTimeMillis() > expireAt;
        }
    }
}
