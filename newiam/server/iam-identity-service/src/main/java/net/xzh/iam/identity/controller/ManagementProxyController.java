package net.xzh.iam.identity.controller;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Set;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.identity.config.IdentityProperties;
import net.xzh.iam.identity.remote.ManagementTokenProvider;

/**
 * 管理面统一代理控制器 (体验面管理后台的唯一后端入口).
 * <p>
 * 路由规则:
 * <ul>
 *   <li>{@code /api/admin/login-policies/**} → 权限中心 (登录边界策略已随 S5 归位权限中心);</li>
 *   <li>其余 {@code /api/admin/**} (users/clients/sessions/records/tenants) →
 *       认证中心身份供给内部 API (路径改写 /api/admin → /api/internal/identity)。</li>
 * </ul>
 * 鉴权: 入站校验管理台用户令牌 (见 SecurityConfig); 出站统一换用管理 M2M 服务令牌
 * (认证中心内部 API 仅接受 M2M 白名单, 用户令牌不放行)。
 * <p>
 * <b>跨域编排</b>: DELETE /api/admin/users/{id} 由本服务编排两步——
 * ①认证中心删除凭据/租户关系/会话 (单域), ②权限中心清理角色绑定与 USER 主体应用授权
 * (best-effort, 失败不影响本地删除结果)。该编排已从认证中心上移至此,
 * 认证中心回归单域职责。
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class ManagementProxyController {

    /** 登录边界策略前缀: 路由至权限中心 */
    private static final String LOGIN_POLICY_PREFIX = "/api/admin/login-policies";

    /** 管理 API 前缀 (入站) */
    private static final String ADMIN_PREFIX = "/api/admin";

    /** 认证中心内部供给 API 前缀 (出站) */
    private static final String AUTH_INTERNAL_PREFIX = "/api/internal/identity";

    private static final Set<String> METHODS_WITH_BODY = Set.of("POST", "PUT", "PATCH", "DELETE");

    private final IdentityProperties properties;
    private final ManagementTokenProvider tokenProvider;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @RequestMapping("/api/admin/**")
    public ResponseEntity<byte[]> proxy(HttpServletRequest request, @RequestBody(required = false) byte[] body) {
        String method = request.getMethod();
        String uri = request.getRequestURI();
        String query = request.getQueryString();

        // 跨域编排: 删除用户 = 认证中心删凭据 + 权限中心清 RBAC
        if ("DELETE".equalsIgnoreCase(method) && uri.matches("^/api/admin/users/[^/]+$")) {
            return orchestrateDeleteUser(uri, query);
        }

        // 常规转发
        String target;
        if (uri.startsWith(LOGIN_POLICY_PREFIX)) {
            target = properties.getAccessBaseUrl() + uri + (query == null ? "" : "?" + query);
        } else {
            target = properties.getAuthBaseUrl() + AUTH_INTERNAL_PREFIX
                    + uri.substring(ADMIN_PREFIX.length()) + (query == null ? "" : "?" + query);
        }
        return forward(method, target, body, request.getContentType());
    }

    /**
     * 删除用户编排: ①解析 userCode → ②认证中心删除 (凭据+租户关系+会话) →
     * ③权限中心清理 RBAC/应用授权 (best-effort)。
     */
    private ResponseEntity<byte[]> orchestrateDeleteUser(String uri, String query) {
        String authUrl = properties.getAuthBaseUrl() + AUTH_INTERNAL_PREFIX
                + uri.substring(ADMIN_PREFIX.length()) + (query == null ? "" : "?" + query);

        // ① 解析 userCode (删除前先取用户档案)
        String userCode;
        try {
            ResponseEntity<byte[]> userResp = forward("GET", authUrl, null, null);
            JsonNode root = objectMapper.readTree(new String(userResp.getBody(), StandardCharsets.UTF_8));
            userCode = root.path("data").path("userCode").asText(null);
        } catch (Exception e) {
            log.warn("[编排] 删除用户前解析 userCode 失败: {}", e.getMessage());
            userCode = null;
        }

        // ② 认证中心单域删除 (凭据/租户关系/会话)
        ResponseEntity<byte[]> deleteResp = forward("DELETE", authUrl, null, null);

        // ③ 权限中心清理 (best-effort, 失败不影响删除结果; 可由评估报告决定是否补偿重试)
        if (userCode != null && deleteResp.getStatusCode().is2xxSuccessful()) {
            String cleanUrl = properties.getAccessBaseUrl() + "/api/admin/users/" + userCode + "/data";
            try {
                ResponseEntity<byte[]> cleanResp = forward("DELETE", cleanUrl, null, null);
                log.info("[编排] 权限中心用户关联清理完成 userCode={}, http={}", userCode, cleanResp.getStatusCode().value());
            } catch (Exception e) {
                log.warn("[编排] 权限中心用户关联清理失败 (不影响本地删除, 需人工核查), userCode={}, error={}",
                        userCode, e.getMessage());
            }
        }
        return deleteResp;
    }

    /** 统一转发: 附 M2M 服务令牌, 401 自愈重试一次, 响应透传 */
    private ResponseEntity<byte[]> forward(String method, String url, byte[] body, String contentType) {
        try {
            HttpResponse<byte[]> resp = doSend(method, url, body, contentType);
            if (resp.statusCode() == 401) {
                log.warn("[代理] 下游 401, 刷新 M2M 令牌后重试一次: {}", url);
                tokenProvider.invalidate();
                resp = doSend(method, url, body, contentType);
            }
            String respContentType = resp.headers().firstValue("Content-Type").orElse("application/json");
            return ResponseEntity.status(resp.statusCode())
                    .header("Content-Type", respContentType)
                    .body(resp.body());
        } catch (Exception e) {
            log.error("[代理] 转发失败: {} {}, error={}", method, url, e.getMessage());
            return ResponseEntity.status(502)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(("{\"code\":502,\"msg\":\"下游服务不可达: " + e.getMessage() + "\",\"data\":null}")
                            .getBytes(StandardCharsets.UTF_8));
        }
    }

    private HttpResponse<byte[]> doSend(String method, String url, byte[] body, String contentType) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + tokenProvider.getToken())
                .header("Accept", "application/json");
        if (body != null && METHODS_WITH_BODY.contains(method.toUpperCase())) {
            builder.header("Content-Type", contentType == null ? "application/json" : contentType);
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
    }
}
