package net.xzh.iam.auth.security.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * 复合 SecurityContextRepository: 先查 DEVICE_SECURITY_CONTEXT, 再查 PORTAL_SECURITY_CONTEXT.
 * <p>
 * 用于 OAuth2 链 (Order 1), 使其能同时读取 OAuth2 登录态和设备验证登录态:
 * <ul>
 *   <li>设备码流程: 用户通过 /device-login 登录, 认证态存入 DEVICE_SECURITY_CONTEXT (由 Order 5 链写入)</li>
 *   <li>授权码流程: 用户通过 /login 登录, 认证态存入 PORTAL_SECURITY_CONTEXT (由本类 saveContext 写入)</li>
 * </ul>
 * <p>
 * 门户安全链 (原 Order 6) 删除后, OAuth2 链 (Order 1) 接管 formLogin,
 * saveContext 需将认证态写入 PORTAL_SECURITY_CONTEXT, 供后续 /oauth2/authorize 读取.
 * 设备验证流程走 Order 5 链, 不经过本类, 不会污染 OAuth2 登录会话.
 */
public final class CompositeSecurityContextRepository implements SecurityContextRepository {

    /**
     * 设备验证流程的 SecurityContext 在会话中的属性键.
     */
    private final String deviceContextKey;

    /**
     * OAuth2 授权登录流程的 SecurityContext 在会话中的属性键.
     */
    private final String portalContextKey;

    public CompositeSecurityContextRepository(String deviceContextKey, String portalContextKey) {
        Assert.hasText(deviceContextKey, "deviceContextKey cannot be empty");
        Assert.hasText(portalContextKey, "portalContextKey cannot be empty");
        this.deviceContextKey = deviceContextKey;
        this.portalContextKey = portalContextKey;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder holder) {
        HttpServletRequest request = holder.getRequest();
        HttpSession session = request.getSession(false);
        if (session != null) {
            // 先查 DEVICE (设备验证流程中优先使用设备登录态)
            SecurityContext ctx = readContextFromSession(session, deviceContextKey);
            if (ctx != null) {
                return ctx;
            }
            // 再查 PORTAL (授权码流程的 OAuth2 登录态)
            ctx = readContextFromSession(session, portalContextKey);
            if (ctx != null) {
                return ctx;
            }
        }
        return SecurityContextHolder.createEmptyContext();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request,
                            HttpServletResponse response) {
        // OAuth2 链 (Order 1) 接管 formLogin,
        // 需将认证态写入 PORTAL_SECURITY_CONTEXT, 供后续 /oauth2/authorize 读取
        if (context == null || context.getAuthentication() == null || !context.getAuthentication().isAuthenticated()) {
            return;
        }
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.setAttribute(portalContextKey, context);
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            return session.getAttribute(deviceContextKey) != null
                    || session.getAttribute(portalContextKey) != null;
        }
        return false;
    }

    /**
     * 从指定的 HTTP 会话中根据键名读取并返回有效的 {@link SecurityContext}.
     * 仅当属性值为 {@code SecurityContext} 且其 {@code Authentication} 已认证时才返回,
     * 否则返回 {@code null}.
     *
     * @param session HTTP 会话, 不得为 {@code null}
     * @param key     会话中存储 SecurityContext 的属性键
     * @return 有效的 {@link SecurityContext}, 若无则返回 {@code null}
     */
    private SecurityContext readContextFromSession(HttpSession session, String key) {
        Object attr = session.getAttribute(key);
        if (attr instanceof SecurityContext sc) {
            Authentication auth = sc.getAuthentication();
            if (auth != null && auth.isAuthenticated()) {
                return sc;
            }
        }
        return null;
    }
}
