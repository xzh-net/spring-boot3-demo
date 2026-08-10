package net.xzh.authserver.security.web;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * 检查 HttpSession 是否已被强制下线 (通过 SessionRegistry 标记为 expired).
 *
 * 如果已过期, 销毁 session 并清除 SecurityContext, 然后继续执行 filterChain
 * (不直接 sendRedirect). 后续的 OAuth2AuthorizationEndpointFilter / AuthorizationFilter
 * 会发现用户未认证, 由 ExceptionTranslationFilter 保存原始请求到 RequestCache
 * 并重定向到登录页. 登录成功后 SavedRequestAwareAuthenticationSuccessHandler
 * 会从 RequestCache 恢复原始请求 (如 /oauth2/authorize?...), 实现强制下线后
 * 重新登录能回到原流程, 而不是跳到默认门户页.
 */
public final class SessionExpirationFilter extends OncePerRequestFilter {

    /**
     * 用于查询和管理 Session 过期信息的注册表.
     */
    private final SessionRegistry sessionRegistry;

    public SessionExpirationFilter(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());
            if (info != null && info.isExpired()) {
                logger.debug("Session " + session.getId() + " is expired, clearing authentication");
                sessionRegistry.removeSessionInformation(session.getId());
                // 销毁 HttpSession (清除其中的 SecurityContext)
                session.invalidate();
                // 清除 SecurityContextHolder 中已加载的 SecurityContext
                // 让后续过滤器认为用户未认证, 触发标准未认证流程
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }
}
