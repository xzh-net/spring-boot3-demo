package net.xzh.authserver.controller.auth;

import java.io.IOException;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.AuthorizationServerConfig;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import org.springframework.security.core.session.SessionRegistry;

/**
 * 自定义 OIDC RP-Initiated Logout 端点.
 * <p>
 * 处理 GET /logout 请求, 执行以下操作:
 * <ol>
 *   <li>从 HttpSession 中提取 OAuth2 登录态 (PORTAL_SECURITY_CONTEXT), 获取用户名</li>
 *   <li>调用 {@link AuthorizationServerConfig#partialLogout} 清除 OAuth2 SSO 会话,
 *       保留管理员/设备验证的登录态 (如果在同一会话中)</li>
 *   <li>撤销该用户通过授权码模式获取的 OAuth2 授权记录 (access_token, refresh_token)</li>
 *   <li>重定向到 post_logout_redirect_uri 参数指定的 URL</li>
 * </ol>
 * <p>
 * <b>为什么不使用 SAS 的 OidcLogoutEndpointFilter:</b>
 * SAS 1.4.1 的 OidcLogoutEndpointFilter 在解码 id_token_hint 时抛出
 * OAuth2AuthenticationException (原因未明, 可能与 JWT 验证或会话状态有关),
 * 导致所有 /logout 请求返回 400 Bad Request。
 * 此自定义控制器绕过该 Filter, 直接处理 /logout 请求。
 * <p>
 * <b>OidcLogoutEndpointFilter 的匹配路径已改为 /oidc/logout</b> (见 AuthorizationServerConfig),
 * 不会再拦截 /logout 请求。
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class LogoutController {

    private final SessionRegistry sessionRegistry;
    private final RedisOAuth2AuthorizationService authorizationService;

    /**
     * 处理 OIDC RP-Initiated Logout 请求.
     * <p>
     * 接收参数 (符合 OIDC RP-Initiated Logout 1.0 规范):
     * <ul>
     *   <li>post_logout_redirect_uri: 登出后的跳转地址 (必填, 由 portal-server 传入)</li>
     *   <li>id_token_hint: ID Token JWT (可选, 本实现不验证, 仅忽略)</li>
     *   <li>state: 透传给 post_logout_redirect_uri 的状态参数 (可选)</li>
     * </ul>
     */
    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        // 1. 从 HttpSession 中提取 OAuth2 登录态, 获取用户名 (用于后续撤销授权)
        //    同时获取 SSO 会话 ID (在 partialLogout 销毁 session 之前)
        HttpSession session = request.getSession(false);
        String principalName = extractPrincipalName(request);
        String ssoSessionId = (session != null) ? session.getId() : null;

        // 2. 调用 partialLogout 清除 OAuth2 SSO 会话
        //    只移除 PORTAL_CONTEXT_KEY, 保留 ADMIN/DEVICE 的登录态
        AuthorizationServerConfig.partialLogout(sessionRegistry, request,
                AuthorizationServerConfig.PORTAL_CONTEXT_KEY);

        // 3. 撤销当前 SSO 会话关联的 OAuth2 授权记录 (客户端会话)
        //    优先按 SSO 会话撤销, 避免多设备场景误伤其他设备;
        //    若 ssoSessionId 为 null 或关联撤销返回 0, fallback 到按用户撤销 (向后兼容)
        int revoked = 0;
        if (ssoSessionId != null) {
            revoked = authorizationService.revokeBySsoSessionId(ssoSessionId);
        }
        if (revoked == 0 && principalName != null) {
            revokeAuthorizationCodeGrants(principalName);
        }

        log.info("[LogoutController] 用户 {} 已登出, SSO 会话已清除", principalName != null ? principalName : "未知");

        // 4. 重定向到登出后跳转地址
        // 兼容两种参数名:
        //   - post_logout_redirect_uri: OIDC RP-Initiated Logout 标准参数 (portal-server 使用)
        //   - redirect: 各客户端应用 (oauth2-callback-web-app / mobile-app) 的自定义参数
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String redirectParam = request.getParameter("redirect");
        String state = request.getParameter("state");

        // 优先使用标准 OIDC 参数, 其次使用 redirect 兼容参数
        String finalRedirectUri = (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank())
                ? postLogoutRedirectUri
                : redirectParam;

        if (finalRedirectUri != null && !finalRedirectUri.isBlank()) {
            String redirectUrl = finalRedirectUri;
            if (state != null && !state.isBlank()) {
                redirectUrl += (finalRedirectUri.contains("?") ? "&" : "?") + "state=" + state;
            }
            response.sendRedirect(redirectUrl);
        } else {
            // 没有 post_logout_redirect_uri, 返回简单的登出成功页面
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("""
                <!DOCTYPE html>
                <html><head><meta charset="UTF-8"><title>登出成功</title></head>
                <body><h2>✅ 您已成功登出</h2>
                <p>认证中心会话已清除。</p></body></html>""");
        }
    }

    /**
     * 从 HttpSession 的 PORTAL_SECURITY_CONTEXT 属性中提取用户名.
     */
    private String extractPrincipalName(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object attr = session.getAttribute(AuthorizationServerConfig.PORTAL_CONTEXT_KEY);
        if (attr instanceof SecurityContext sc) {
            Authentication auth = sc.getAuthentication();
            if (auth != null && auth.isAuthenticated()) {
                return auth.getName();
            }
        }
        return null;
    }

    /**
     * 撤销该用户通过授权码模式 (authorization_code) 产生的所有 OAuth2Authorization 记录.
     * <p>
     * 只清理 authorization_code 类型, 因为:
     * <ul>
     *   <li>authorization_code: 完全依赖 OAuth2 SSO 会话, 登出=会话终结, 必须撤销</li>
     *   <li>password: 用账号密码直接换 token, 不依赖 SSO, 不能误删</li>
     *   <li>device_code / client_credentials: 独立流程, 不受 SSO 登出影响</li>
     * </ul>
     */
    private void revokeAuthorizationCodeGrants(String principalName) {
        try {
            int revoked = 0;
            for (OAuth2Authorization auth : authorizationService.findByPrincipal(principalName)) {
                if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(auth.getAuthorizationGrantType())) {
                    authorizationService.revoke(auth);
                    revoked++;
                }
            }
            if (revoked > 0) {
                log.info("[LogoutController] 已撤销 {} 的 {} 条 authorization_code 型 OAuth2 授权",
                        principalName, revoked);
            }
        } catch (Exception e) {
            log.warn("[LogoutController] 撤销授权失败 principal={}: {}", principalName, e.getMessage());
        }
    }
}
