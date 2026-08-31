package net.xzh.iam.auth.remote;

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
import net.xzh.iam.auth.config.AuthServerProperties;

/**
 * 服务令牌供给 (M2M client_credentials).
 * <p>
 * 认证中心调用权限中心 (iam-access-service) 内部决策接口时, 以 client_credentials
 * 换取 resource-server 服务凭证令牌, 进程内按令牌有效期缓存 TTL 供
 * {@link AccessDecisionClient} 复用。
 * <p>
 * 干净切割后本类只保留一种服务凭证 (resource-server): 管理面 M2M 凭证 (admin-m2m)
 * 的使用方已随管理 API 一并迁往 iam-identity-service。
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
     * 获取服务凭证令牌 (resource-server), 进程内缓存.
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
            TokenResponse tr = acquire(properties.getServiceTokenClientId(),
                    properties.getServiceTokenClientSecret());
            CacheEntry<String> entry = new CacheEntry<>(tr.token(),
                    System.currentTimeMillis() + Math.max(tr.expiresInSeconds() - TOKEN_SAFE_MARGIN_SECONDS, 30) * 1000);
            tokenCache = entry;
            return tr.token();
        }
    }

    /** 判定缓存失效 (如目标端返回 401) 后调用, 下次获取将强制刷新 */
    public void invalidate() {
        tokenCache = null;
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