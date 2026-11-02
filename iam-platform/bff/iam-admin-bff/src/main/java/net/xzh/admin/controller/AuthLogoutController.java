package net.xzh.admin.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
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
 * <p>
 * <b>本地清理三步 (生产化三件套之三):</b>
 * <ol>
 *   <li>显式移除 OAuth2AuthorizedClient (access/refresh token 记录) —— 双保险:
 *       HttpSession 版 repository 下 session.invalidate() 已连带清除该属性,
 *       但显式调用与存储实现无关 (若将来换回进程内 InMemory 实现, 清理依然生效);</li>
 *   <li>invalidate HttpSession (Spring Session → Redis 键删除, ADMIN_SERVER_SESSION 失效);</li>
 *   <li>清 SecurityContextHolder, 再走 9000 端会话注销。</li>
 * </ol>
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthLogoutController {

    private static final String REGISTRATION_ID = "admin-app";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 1. 显式移除本地 token 记录 (须在 invalidate 与 clearContext 之前: 分别依赖 session 与 authentication)
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                authorizedClientRepository.removeAuthorizedClient(REGISTRATION_ID, authentication, request, response);
                log.debug("[logout] 已移除本地 OAuth2AuthorizedClient 记录");
            }
        } catch (Exception e) {
            // 清理失败不阻断登出: 后续 invalidate 仍会销毁 session 属性, 9000 侧端会话照常注销
            log.warn("[logout] 移除本地 token 记录失败 (忽略): {}", e.getMessage());
        }

        // 2. 清理本地 (admin-bff) 会话
        request.getSession().invalidate();
        SecurityContextHolder.clearContext();

        // 3. 跳认证中心自定义 RP-Initiated Logout 端点
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("admin-app");
        String issuerUri = registration.getProviderDetails().getIssuerUri();
        String logoutUri = issuerUri + "/logout?post_logout_redirect_uri="
                + URLEncoder.encode("http://localhost:8001/logged-out", StandardCharsets.UTF_8);
        log.info("[logout] 重定向认证中心端会话注销: {}", issuerUri);
        response.sendRedirect(logoutUri);
    }
}