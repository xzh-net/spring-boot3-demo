package net.xzh.admin.controller;

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
 * 接收管理后台页面 (iam-admin-web 8001) 转发的 /api/** 请求,
 * 附加当前登录用户 (admin-app) 的 Bearer Token 后转发到:
 * <ul>
 *  <li>认证中心 (9000): /api/admin/users|clients|sessions|records|directory</li>
 *  <li>资源中心 (9010): /api/admin/roles|permissions</li>
 * </ul>
 * ROLE_ADMIN 权限由对端 introspection 校验。
 */
@Slf4j
@RestController
@RequestMapping("/api")
public class ApiProxyController {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final String authCenterBaseUrl;
    private final String resourceServiceBaseUrl;

    public ApiProxyController(
            @Value("${iam.auth-center-base-url}") String authCenterBaseUrl,
            @Value("${iam.resource-service-base-url}") String resourceServiceBaseUrl) {
        this.authCenterBaseUrl = authCenterBaseUrl;
        this.resourceServiceBaseUrl = resourceServiceBaseUrl;
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
     * 按路径前缀决定转发目标.
     */
    private String resolveBase(String uri) {
        if (uri.startsWith("/api/admin/roles")
                || uri.startsWith("/api/admin/permissions")
                || uri.startsWith("/api/admin/user-roles")) {
            return resourceServiceBaseUrl;
        }
        return authCenterBaseUrl;
    }
}