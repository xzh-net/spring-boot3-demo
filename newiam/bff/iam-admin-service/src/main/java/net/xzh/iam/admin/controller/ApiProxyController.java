package net.xzh.iam.admin.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * 管理 API 透传代理.
 * <p>
 * 接收管理后台页面 (iam-admin-web :8201) 的 /api/** 请求,
 * 附加当前登录用户 (admin-app) 的 Bearer Token 后按新拓扑转发:
 * <ul>
 *  <li>身份管理面 (9020): /api/admin/users|clients|sessions|records|tenants
 *      (管理面编排后经 M2M 调认证中心内部供给 API)</li>
 *  <li>权限中心 (9010): /api/admin/roles|permissions|user-roles|applications|
 *      endpoint-policies|login-policies (登录边界策略已随 S5 归位权限中心)</li>
 *  <li>开放平台 (9030): /api/admin/capabilities|capability-subscriptions</li>
 * </ul>
 * ADMIN_SERVICE_TOKEN 准入由对端 introspection 校验。
 */
@Slf4j
@RestController
@RequestMapping("/api")
public class ApiProxyController {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final String identityBaseUrl;
    private final String accessBaseUrl;
    private final String openBaseUrl;

    public ApiProxyController(
            @Value("${iam.identity-base-url}") String identityBaseUrl,
            @Value("${iam.access-base-url}") String accessBaseUrl,
            @Value("${iam.open-base-url}") String openBaseUrl) {
        this.identityBaseUrl = identityBaseUrl;
        this.accessBaseUrl = accessBaseUrl;
        this.openBaseUrl = openBaseUrl;
    }

    /**
     * 通用透传代理端点 (处理所有 HTTP 方法与子路径).
     */
    @RequestMapping("/**")
    public void proxy(HttpServletRequest request, HttpServletResponse response,
                      @RegisteredOAuth2AuthorizedClient("admin-app") OAuth2AuthorizedClient authorizedClient)
            throws IOException, InterruptedException {
        String uri = request.getRequestURI();
        String query = request.getQueryString();

        String base = resolveBase(uri);
        if (base == null) {
            response.setStatus(404);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"code\":404,\"msg\":\"未知管理端点: " + uri + "\",\"data\":null}");
            return;
        }
        String target = base + uri + (query != null ? "?" + query : "");
        log.debug("[proxy] {} {} -> {}", request.getMethod(), request.getRequestURI(), target);

        String method = request.getMethod();
        byte[] body = null;
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            body = request.getInputStream().readAllBytes();
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(target))
                .timeout(Duration.ofSeconds(10));

        if (body != null && body.length > 0) {
            String contentType = request.getContentType();
            if (contentType != null) {
                builder.header("Content-Type", contentType);
            }
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }

        if (authorizedClient != null && authorizedClient.getAccessToken() != null) {
            builder.header("Authorization", "Bearer " + authorizedClient.getAccessToken().getTokenValue());
        }
        builder.header("Accept", "application/json");

        HttpResponse<byte[]> resp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        response.setStatus(resp.statusCode());
        resp.headers().firstValue("Content-Type")
                .ifPresentOrElse(ct -> response.setContentType(ct),
                        () -> response.setContentType("application/json; charset=utf-8"));
        response.getOutputStream().write(resp.body());
        response.getOutputStream().flush();
    }

    /**
     * 按路径前缀决定转发目标 (新拓扑: 管理面/权限中心/开放平台).
     * 认证中心不再直接暴露 /api/admin, 未匹配路径一律 404 拒绝。
     */
    private String resolveBase(String uri) {
        if (uri.startsWith("/api/admin/users")
                || uri.startsWith("/api/admin/clients")
                || uri.startsWith("/api/admin/sessions")
                || uri.startsWith("/api/admin/records")
                || uri.startsWith("/api/admin/tenants")) {
            return identityBaseUrl;
        }
        if (uri.startsWith("/api/admin/roles")
                || uri.startsWith("/api/admin/permissions")
                || uri.startsWith("/api/admin/user-roles")
                || uri.startsWith("/api/admin/applications")
                || uri.startsWith("/api/admin/endpoint-policies")
                || uri.startsWith("/api/admin/login-policies")) {
            return accessBaseUrl;
        }
        if (uri.startsWith("/api/admin/capabilities")
                || uri.startsWith("/api/admin/capability-subscriptions")) {
            return openBaseUrl;
        }
        return null;
    }
}