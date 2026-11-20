package net.xzh.iam.auth.security.web;

import java.io.IOException;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * 检查 HttpSession 是否已被强制下线 (通过 SessionRegistry 标记为 expired).
 *
 * <p>如果已过期: 销毁 session、清除 SecurityContext, <b>显式保存原始请求</b> 后
 * 带 {@code ?expired} 参数跳登录页 —— 用户能看到「会话已过期或已在其他设备登录」
 * (A-P1-4 踢出可感知), 登录成功后由 SavedRequestAwareAuthenticationSuccessHandler
 * 从 RequestCache 恢复原始请求 (如 /oauth2/authorize?...), 回到原流程。</p>
 *
 * <p><b>为什么不继续链交给 ExceptionTranslationFilter:</b> 本过滤器排在
 * ConcurrentSessionFilter (expiredUrl 的唯一消费者) 之前, 继续链时会先
 * removeSessionInformation + invalidate, ConcurrentSessionFilter 查不到过期记录,
 * expiredUrl 永不触发 —— 实测被踢落点是裸 login.html (无参数), 用户无从得知被踢原因。
 * 故改为显式 saveRequest + 带参跳转, 同时保住「可感知」与「回原流程」。</p>
 */
public final class SessionExpirationFilter extends OncePerRequestFilter {

    /**
     * 用于查询和管理 Session 过期信息的注册表.
     */
    private final SessionRegistry sessionRegistry;

    /**
     * 与 ExceptionTranslationFilter 默认一致的请求缓存 (同 SPRING_SECURITY_SAVED_REQUEST 属性),
     * 保证登录后 SavedRequestAwareAuthenticationSuccessHandler 能取回.
     */
    private final RequestCache requestCache = new HttpSessionRequestCache();

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
                SecurityContextHolder.clearContext();
                // 显式保存原始请求 (session 刚被销毁, 先确保新 session 存在), 再带 expired 标记跳登录页:
                // 既让用户知道被踢原因, 登录后又能回到原流程 (原靠继续链由 ETF 保存, 但那样落点无参数)
                request.getSession(true);
                requestCache.saveRequest(request, response);
                response.sendRedirect(request.getContextPath() + "/login.html?expired");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}
