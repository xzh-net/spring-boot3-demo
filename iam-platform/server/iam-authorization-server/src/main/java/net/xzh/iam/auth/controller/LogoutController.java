package net.xzh.iam.auth.controller;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.OAuth2RegisteredClient;
import net.xzh.iam.auth.mapper.OAuth2RegisteredClientMapper;
import net.xzh.iam.auth.security.AuthorizationServerConfig;
import net.xzh.iam.auth.security.repository.RedisOAuth2AuthorizationService;

/**
 * 自定义 OIDC RP-Initiated Logout 端点.
 * <p>
 * 处理 GET /logout 请求, 执行以下操作:
 * <ol>
 *   <li>从 HttpSession 中提取 OAuth2 登录态 (OAUTH2_SECURITY_CONTEXT), 获取用户名</li>
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
    private final OAuth2RegisteredClientMapper clientMapper;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * 处理 OIDC RP-Initiated Logout 请求.
     * <p>
     * 接收参数 (符合 OIDC RP-Initiated Logout 1.0 规范):
     * <ul>
     *   <li>post_logout_redirect_uri: 登出后的跳转地址 (必填, 由 iam-portal-bff 传入)</li>
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
        //    只移除 OAUTH2_CONTEXT_KEY, 保留 ADMIN/DEVICE 的登录态
        AuthorizationServerConfig.partialLogout(sessionRegistry, request,
                AuthorizationServerConfig.OAUTH2_CONTEXT_KEY);

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

        // 4. 重定向到登出后跳转地址 (A-P1-6: 目标须同源相对路径, 或逐字匹配注册客户端
        //    登记的 post_logout_redirect_uris; 带 id_token_hint 时收窄到该客户端自己的登记地址)
        // 兼容两种参数名:
        //   - post_logout_redirect_uri: OIDC RP-Initiated Logout 标准参数 (iam-portal-bff 使用)
        //   - redirect: 各客户端应用 (iam-client-web-demo 等) 的自定义参数
        String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
        String redirectParam = request.getParameter("redirect");
        String state = request.getParameter("state");

        // 优先使用标准 OIDC 参数, 其次使用 redirect 兼容参数
        String finalRedirectUri = (postLogoutRedirectUri != null && !postLogoutRedirectUri.isBlank())
                ? postLogoutRedirectUri
                : redirectParam;

        if (finalRedirectUri != null && !finalRedirectUri.isBlank()) {
            String target = finalRedirectUri.trim();
            if (isLogoutRedirectAllowed(target, request.getParameter("id_token_hint"))) {
                String redirectUrl = target;
                if (state != null && !state.isBlank()) {
                    // state 重编码, 防止借参数拼接注入 (A-P1-6)
                    redirectUrl += (target.contains("?") ? "&" : "?")
                            + "state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
                }
                response.sendRedirect(redirectUrl);
                return;
            }
            // 目标未通过校验: 不跳转, 落登出成功页 (open-redirect 防线, A-P1-6)
            log.warn("[LogoutController] 拒绝未登记的登出跳转目标: {} (来源 ip={})",
                    target, request.getRemoteAddr());
        }

        // 没有跳转地址 (或目标被拒绝), 返回简单的登出成功页面
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("""
            <!DOCTYPE html>
            <html><head><meta charset="UTF-8"><title>登出成功</title></head>
            <body><h2>✅ 您已成功登出</h2>
            <p>认证中心会话已清除。</p></body></html>""");
    }

    /**
     * 登出跳转目标校验 (A-P1-6, 替代原未接线的 ALLOWED_REDIRECT_HOSTS 死代码):
     * <ol>
     *   <li>同源相对路径 ({@code /} 开头, 排除 {@code //} 与 {@code /\} 协议相对变体) → 放行 (跳不出本站);</li>
     *   <li>仅 http/https 绝对 URL, 且<b>逐字匹配</b>某注册客户端的 post_logout_redirect_uris → 放行
     *       (数据源 = 客户端管理页维护的 oauth2_registered_client 表, 零硬编码);</li>
     *   <li>携带 id_token_hint 时收窄到 hint.aud 指向的那一个客户端 (A″ 逐客户端);</li>
     *   <li>全不中 → 拒绝跳转, 落登出成功页 + log.warn。</li>
     * </ol>
     */
    private boolean isLogoutRedirectAllowed(String target, String idTokenHint) {
        if (target.startsWith("/") && !target.startsWith("//") && !target.startsWith("/\\")) {
            return true;
        }
        URI u;
        try {
            u = new URI(target);
        } catch (Exception e) {
            return false;
        }
        String scheme = u.getScheme();
        if (u.getHost() == null
                || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            return false; // javascript:/data:/协议相对/畸形 URL 一律拒
        }
        // A″: 带 hint → 只查 aud 指向客户端的登记表; 缺失/解码失败 → 查全部客户端 (union)
        List<String> candidateClients = decodeAudience(idTokenHint);
        for (OAuth2RegisteredClient client : clientMapper.selectList(null)) {
            if (candidateClients != null && !candidateClients.contains(client.getClientId())) {
                continue;
            }
            String registered = client.getPostLogoutRedirectUris();
            if (registered == null || registered.isBlank()) {
                continue;
            }
            for (String allowed : registered.split(",")) {
                if (target.equals(allowed.trim())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 从 id_token_hint 解出 aud (client_id) 列表 —— 仅 base64 解码 payload, 不验签。
     * <p>安全性说明: 伪造 aud 最多在「各客户端已登记的合法地址」之间切换校验范围,
     * 永远跳不出登记表 —— 主防线是登记表逐字匹配本身, hint 收窄是第二层。
     * 解码失败按无 hint 处理 (union), 不影响主防线。</p>
     */
    private static List<String> decodeAudience(String idTokenHint) {
        if (idTokenHint == null || idTokenHint.isBlank()) {
            return null;
        }
        try {
            String[] parts = idTokenHint.split("\\.");
            if (parts.length < 2) {
                return null;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode aud = OBJECT_MAPPER.readTree(payload).get("aud");
            if (aud == null) {
                return null;
            }
            List<String> ids = new ArrayList<>();
            if (aud.isTextual()) {
                ids.add(aud.asText());
            } else if (aud.isArray()) {
                aud.forEach(node -> {
                    if (node.isTextual()) {
                        ids.add(node.asText());
                    }
                });
            }
            return ids.isEmpty() ? null : ids;
        } catch (Exception e) {
            log.debug("[LogoutController] id_token_hint 解码失败, 按无 hint 处理: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 从 HttpSession 的 OAUTH2_SECURITY_CONTEXT 属性中提取用户名.
     */
    private String extractPrincipalName(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object attr = session.getAttribute(AuthorizationServerConfig.OAUTH2_CONTEXT_KEY);
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
