package net.xzh.authserver.remote;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.AuthServerProperties;

/**
 * 资源中心 (iam-resource-service) 远程角色供给 (改造清单 D6 接入).
 * <p>
 * 认证中心签发令牌前的准入判定需要「用户业务 RBAC 角色」, 而角色权威在
 * 资源中心 iam_authorization 库。本组件以 {@code client_credentials}
 * 服务令牌 (resource-server 客户端, PORTAL_SERVICE_TOKEN) 调用资源中心内部接口
 * {@code /api/internal/user/{userCode}/roles} 获取用户角色 (token sub 即 user_code)。
 * <ul>
 *   <li>用户角色与服务令牌均做进程内 TTL 缓存, 降低跨服务调用频率;</li>
 *   <li>资源中心不可达或解析失败时抛出 {@link IllegalStateException},
 *       由调用方按「无法证明允许」拒绝签发 (fail-closed)。</li>
 * </ul>
 */
@Slf4j
@Component
public class RemoteRoleService {

    /** 角色缓存 TTL (秒) */
    private static final long ROLES_TTL_SECONDS = 30;

    private final AuthServerProperties properties;
    private final ServiceTokenProvider serviceTokenProvider;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** user: roles 缓存 (带过期时间) */
    private final ConcurrentHashMap<String, CacheEntry<Set<String>>> rolesCache = new ConcurrentHashMap<>();

    public RemoteRoleService(AuthServerProperties properties, ServiceTokenProvider serviceTokenProvider, ObjectMapper objectMapper) {
        this.properties = properties;
        this.serviceTokenProvider = serviceTokenProvider;
        this.objectMapper = objectMapper;
    }

    /**
     * 获取用户业务角色编码集合 (含管理端业务角色编码 ADMIN), 进程内缓存。
     *
     * @param userCode 业务用户编码 (令牌 sub)
     * @throws IllegalStateException 资源中心不可达或响应异常时抛出
     */
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
        String url = properties.getResourceServiceBaseUrl()
                + "/api/internal/user/" + encode(userCode) + "/roles";
        String token = serviceTokenProvider.getToken();
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
                serviceTokenProvider.invalidate();
                token = serviceTokenProvider.getToken();
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

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private record CacheEntry<T>(T value, long expireAt) {
        boolean expired() {
            return System.currentTimeMillis() > expireAt;
        }
    }
}
