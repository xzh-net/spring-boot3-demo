package net.xzh.iam.auth.remote;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.config.AuthServerProperties;

/**
 * 权限中心 (iam-access-service) 登录准入决策客户端 (PDP 问询).
 * <p>
 * 干净切割后的唯一角色供给通道: 认证中心不再本地评估准入策略, 也不再拉取全量角色,
 * 一切"该用户能否登录该客户端"的判定都问询权限中心的统一决策接口:
 * <pre>
 * POST {accessServiceBaseUrl}/api/internal/access/decide
 * body: {"userCode": "...", "clientId": "..."}   (clientId 可空 = 仅解析角色不做准入闸门)
 * resp: {"code":200, "data":{"allowed":true, "roles":["USER"]}}
 * </pre>
 * 规则 (client_policy) 与事实 (RBAC) 都在权限中心本地闭环, 本类只传达裁决结果。
 * <p>
 * <b>SWR 缓存语义</b> (stale-while-revalidate):
 * <ul>
 *   <li>新鲜窗口 ({@code decideCacheTtlSeconds}, 默认 30s) 内直接命中缓存;</li>
 *   <li>过期后同步刷新; 刷新失败时沿用最后一次<b>真实判定</b>, 直至 max-stale
 *       ({@code decideMaxStaleSeconds}, 默认 600s) —— 以真实历史事实保证权限中心宕机时
 *       管理端仍可登录, 取代旧版按 user_label 展示字段猜测角色的降级 hack;</li>
 *   <li>超过 max-stale 仍不可达 → 抛出异常, 调用方 fail-closed 明确拒绝 (无任何猜测成分)。</li>
 * </ul>
 */
@Slf4j
@Component
public class AccessDecisionClient {

    private final AuthServerProperties properties;
    private final ServiceTokenProvider serviceTokenProvider;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** SWR 缓存: key = userCode|clientId, value = 最后一次真实判定 + 抓取时间 */
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public AccessDecisionClient(AuthServerProperties properties,
            ServiceTokenProvider serviceTokenProvider, ObjectMapper objectMapper) {
        this.properties = properties;
        this.serviceTokenProvider = serviceTokenProvider;
        this.objectMapper = objectMapper;
    }

    /** 登录准入决策结果: allowed=是否放行, roles=用户业务角色快照 (供令牌 claims 注入) */
    public record DecideResult(boolean allowed, Set<String> roles) {
    }

    /**
     * 问询准入决策 (带 SWR 缓存).
     *
     * @param userCode 业务用户编码 (令牌 sub)
     * @param clientId 目标客户端; 传 null 表示仅解析角色、不做客户端准入闸门
     * @throws IllegalStateException 权限中心不可达且缓存超出 max-stale 窗口
     */
    public DecideResult decide(String userCode, String clientId) {
        String key = userCode + "|" + (clientId == null ? "" : clientId);
        long now = System.currentTimeMillis();
        long ttlMillis = properties.getDecideCacheTtlSeconds() * 1000L;
        long maxStaleMillis = properties.getDecideMaxStaleSeconds() * 1000L;

        CacheEntry entry = cache.get(key);
        if (entry != null && now - entry.fetchedAt < ttlMillis) {
            return entry.value;
        }
        try {
            DecideResult fresh = fetch(userCode, clientId);
            cache.put(key, new CacheEntry(fresh, now));
            return fresh;
        } catch (Exception e) {
            if (entry != null && now - entry.fetchedAt < ttlMillis + maxStaleMillis) {
                log.warn("[decide] 权限中心不可达, SWR 沿用最后真实判定 (age={}s), key={}, error={}",
                        (now - entry.fetchedAt) / 1000, key, e.getMessage());
                return entry.value;
            }
            throw new IllegalStateException("登录准入决策不可用 (权限中心不可达且无可用缓存判定): " + e.getMessage(), e);
        }
    }

    /**
     * 仅解析用户业务角色 (无客户端上下文时使用, 如 UserDetailsService 构建令牌 authorities).
     *
     * @throws IllegalStateException 权限中心不可达且缓存超出 max-stale 窗口
     */
    public Set<String> resolveRoles(String userCode) {
        return decide(userCode, null).roles();
    }

    private DecideResult fetch(String userCode, String clientId) {
        String url = properties.getAccessServiceBaseUrl() + "/api/internal/access/decide";
        String body = "{\"userCode\":\"" + jsonEscape(userCode) + "\",\"clientId\":"
                + (clientId == null ? "null" : "\"" + jsonEscape(clientId) + "\"") + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer " + serviceTokenProvider.getToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = sendWithTokenHeal(url, body);
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("decide 接口返回 HTTP " + resp.statusCode());
        }
        return parse(resp.body());
    }

    /** 401 时判定服务令牌失效 (如 Redis 被清空), 强制刷新后重试一次 (自愈) */
    private HttpResponse<String> sendWithTokenHeal(String url, String body) {
        try {
            return doSend(url, body);
        } catch (IllegalStateExceptionWith401 e) {
            log.warn("[decide] 服务令牌失效 (401), 强制刷新后重试一次");
            serviceTokenProvider.invalidate();
            try {
                return doSend(url, body);
            } catch (IllegalStateExceptionWith401 e2) {
                throw new IllegalStateException("decide 接口重试后仍 401", e2);
            }
        }
    }

    private HttpResponse<String> doSend(String url, String body) throws IllegalStateExceptionWith401 {
        HttpRequest request;
        try {
            request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Bearer " + serviceTokenProvider.getToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 401) {
                throw new IllegalStateExceptionWith401();
            }
            return resp;
        } catch (IllegalStateExceptionWith401 e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("调用 decide 接口失败: " + e.getMessage(), e);
        }
    }

    private DecideResult parse(String json) {
        try {
            JsonNode root = objectMapper.readTree(json);
            int code = root.path("code").asInt();
            if (code != 200) {
                throw new IllegalStateException("decide 业务码 " + code + ": " + root.path("msg").asText());
            }
            JsonNode data = root.path("data");
            boolean allowed = data.path("allowed").asBoolean(false);
            Set<String> roles = new LinkedHashSet<>();
            JsonNode rolesNode = data.path("roles");
            if (rolesNode.isArray()) {
                rolesNode.forEach(n -> {
                    String r = n.asText();
                    if (!r.isBlank()) {
                        roles.add(r);
                    }
                });
            }
            return new DecideResult(allowed, roles);
        } catch (Exception e) {
            throw new IllegalStateException("decide 响应解析失败: " + e.getMessage(), e);
        }
    }

    private static String jsonEscape(String v) {
        return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static final class IllegalStateExceptionWith401 extends RuntimeException {
    }

    private record CacheEntry(DecideResult value, long fetchedAt) {
    }
}
