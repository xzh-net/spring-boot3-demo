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
 * 接收管理后台页面 (iam-admin-web 8001) 转发的 /admin/** 请求,
 * 附加当前登录用户 (admin-app) 的 Bearer Token 后转发到认证中心单服务实例 (9000)。
 * A-P2-2/2-3: 单服务合并后无分流需求, 全路径统一 iam.auth-center-base-url
 * (原 resolveBase 双目标 if/else 与 iam.resource-service-base-url 键已删除)。
 * Bearer 权限由对端自省 + 端点准入校验。
 */
@Slf4j
@RestController
@RequestMapping("/admin")
public class ApiProxyController {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private final String authCenterBaseUrl;

    public ApiProxyController(@Value("${iam.auth-center-base-url}") String authCenterBaseUrl) {
        this.authCenterBaseUrl = authCenterBaseUrl;
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

        String target = authCenterBaseUrl + uri + (query != null ? "?" + query : "");
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
}