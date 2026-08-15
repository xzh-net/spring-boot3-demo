package net.xzh.admin.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * 登出: 清理本地会话并跳转认证中心 RP-Initiated Logout (端会话注销).
 * <p>
 * 认证中心的自定义登录出端点为 {@code {issuer}/logout} (LogoutController):
 * 默认 SAS 的 {@code /connect/logout} 已被覆盖且未映射, 直接请求会 404;
 * 自定义端点会清理 SSO 会话并撤销授权码授权, 完成后按 {@code post_logout_redirect_uri}
 * 重定向到 admin-app 客户端注册的登出完成页 (http://localhost:8001/logged-out)。
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthLogoutController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 1. 清理本地 (admin-service) 会话
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();

        // 2. 跳认证中心自定义 RP-Initiated Logout 端点
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("admin-app");
        String issuerUri = registration.getProviderDetails().getIssuerUri();
        String logoutUri = issuerUri + "/logout?post_logout_redirect_uri="
                + URLEncoder.encode("http://localhost:8001/logged-out", StandardCharsets.UTF_8);
        log.info("[logout] 重定向认证中心端会话注销: {}", issuerUri);
        response.sendRedirect(logoutUri);
    }
}