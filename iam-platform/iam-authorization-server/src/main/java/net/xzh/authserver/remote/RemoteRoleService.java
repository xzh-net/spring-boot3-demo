package net.xzh.authserver.remote;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.AuthServerProperties;

/**
 * 璧勬簮涓績 (iam-resource-service) 杩滅▼瑙掕壊渚涚粰 (鏀归€犳竻鍗?D6 鎺ュ叆).
 * <p>
 * 璁よ瘉涓績绛惧彂浠ょ墝鍓嶇殑鍑嗗叆鍒ゅ畾闇€瑕併€岀敤鎴蜂笟鍔?RBAC 瑙掕壊銆? 鑰岃鑹叉潈濞佸湪
 * 璧勬簮涓績 iam_authorization 搴撱€傛湰缁勪欢浠?{@code client_credentials}
 * 鏈嶅姟浠ょ墝 (resource-server 瀹㈡埛绔? ROLE_SERVICE) 璋冪敤璧勬簮涓績鍐呴儴鎺ュ彛
 * {@code /api/internal/user/{userCode}/roles} 鑾峰彇鐢ㄦ埛瑙掕壊 (token sub 鍗?user_code)銆? * <ul>
 *   <li>鐢ㄦ埛瑙掕壊涓庢湇鍔′护鐗屽潎鍋氳繘绋嬪唴 TTL 缂撳瓨, 闄嶄綆璺ㄦ湇鍔¤皟鐢ㄩ鐜?</li>
 *   <li>璧勬簮涓績涓嶅彲杈?瑙ｆ瀽澶辫触鏃舵姏鍑?{@link IllegalStateException},
 *       鐢辫皟鐢ㄦ柟鎸夈€屾棤娉曡瘉鏄庡厑璁搞€嶆嫆缁濈鍙?(fail-closed)銆?/li>
 * </ul>
 */
@Slf4j
@Component
public class RemoteRoleService {

    /** 瑙掕壊/浠ょ墝缂撳瓨 TTL (绉? */
    private static final long ROLES_TTL_SECONDS = 30;
    private static final long TOKEN_SAFE_MARGIN_SECONDS = 60;

    private final AuthServerProperties properties;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** user: roles 缂撳瓨 (甯﹁繃鏈熸椂闂? */
    private final ConcurrentHashMap<String, CacheEntry<Set<String>>> rolesCache = new ConcurrentHashMap<>();
    private volatile CacheEntry<String> tokenCache;

    public RemoteRoleService(AuthServerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * 鑾峰彇鐢ㄦ埛涓氬姟瑙掕壊缂栫爜闆嗗悎 (濡?ROLE_ADMIN), 杩涚▼鍐呯紦瀛樸€?     *
     * @param userCode 涓氬姟鐢ㄦ埛缂栫爜 (浠ょ墝 sub)
     * @throws IllegalStateException 璧勬簮涓績涓嶅彲杈炬垨鍝嶅簲寮傚父鏃舵姏鍑?     */
    public Set<String> getUserRoles(String userCode) {
        CacheEntry<Set<String>> entry = rolesCache.get(userCode);
        if (entry != null && !entry.expired()) {
            return entry.value;
        }
        Set<String> roles = fetchRoles(userCode);
        rolesCache.put(userCode, new CacheEntry<>(roles, System.currentTimeMillis() + ROLES_TTL_SECONDS * 1000));
        return roles;
    }

    /**
     * 调用资源中心内部角色接口 (D6)。
     * <p>
     * 401 时判定为 service token 在 Redis 中失效/已过期 (如清理 Redis 后
     * 授权记录被全部清空), 将缓存判定为无效后重试一次; 以此达到自愈,
     * 用户清空 Redis 后 auth-server 无需重启。
     */
    private Set<String> fetchRoles(String userCode) {
        String token = acquireServiceToken();
        String url = properties.getResourceServiceBaseUrl()
                + "/api/internal/user/" + encode(userCode) + "/roles";
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 401) {
                log.warn("[RemoteRole] 角色接口返回 HTTP 401, 判定 service token 已失效 (Redis 可能被清空), 强制刷新后重试一次. userCode={}", userCode);
                tokenCache = null;
                token = acquireServiceToken();
                HttpRequest retryRequest = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(5))
                        .header("Authorization", "Bearer " + token)
                        .header("Accept", "application/json")
                        .GET()
                        .build();
                resp = httpClient.send(retryRequest, HttpResponse.BodyHandlers.ofString());
            }
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("角色接口返回 HTTP " + resp.statusCode());
            }
            JsonNode root = objectMapper.readTree(resp.body());
            int code = root.path("code").asInt();
            if (code != 200) {
                throw new IllegalStateException("角色接口业务码 " + code + ": " + root.path("msg").asText());
            }
            JsonNode rolesNode = root.path("data").path("roles");
            Set<String> roles = new LinkedHashSet<>();
            if (rolesNode.isArray()) {
                rolesNode.forEach(n -> {
                    String role = n.asText();
                    if (!role.isBlank()) {
                        roles.add(role);
                    }
                });
            }
            log.debug("[RemoteRole] userCode={}, roles={}", userCode, roles);
            return roles;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("调用资源中心角色接口失败 userCode=" + userCode + ": " + e.getMessage(), e);
        }
    }

    /**
     * 鑾峰彇鏈嶅姟浠ょ墝: 浠?resource-server 瀹㈡埛绔?client_credentials 鎹㈠彇, 杩涚▼鍐呯紦瀛樸€?     */
    private String acquireServiceToken() {
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
                    throw new IllegalStateException("鏈嶅姟浠ょ墝鎺ュ彛杩斿洖 HTTP " + resp.statusCode());
                }
                JsonNode root = objectMapper.readTree(resp.body());
                String token = root.path("access_token").asText();
                if (token.isBlank()) {
                    throw new IllegalStateException("鏈嶅姟浠ょ墝鍝嶅簲缂哄皯 access_token");
                }
                long expiresIn = root.path("expires_in").asLong(3600);
                long ttl = Math.max(expiresIn - TOKEN_SAFE_MARGIN_SECONDS, 30) * 1000;
                tokenCache = new CacheEntry<>(token, System.currentTimeMillis() + ttl);
                return token;
            } catch (Exception e) {
                throw new IllegalStateException("鑾峰彇鏈嶅姟浠ょ墝澶辫触: " + e.getMessage(), e);
            }
        }
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record CacheEntry<T>(T value, long expireAt) {
        boolean expired() {
            return System.currentTimeMillis() > expireAt;
        }
    }
}