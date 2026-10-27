package net.xzh.iam.auth.security.web;

import java.io.IOException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.IssuanceAdmissionService;

/**
 * 授权端点签发准入过滤器 (混合登录隔离).
 * <p>
 * 在 {@code /oauth2/authorize} 签发授权码之前先做「该用户能否登录该客户端」判定
 * (用户 RBAC 码 ∩ 客户端 scope 展开码, 见 {@link IssuanceAdmissionService}): 不合规直接
 * 302 回登录页 {@code /login.html?error=access_denied} (与密码错误的失败体验一致, 提示语区分),
 * 不向客户端下发授权码。审计日志在服务端记录 (客户端 + 用户 + 结论), 可归因、可追溯。
 * <p>
 * 该闸为 fail-closed: 决策依赖 scope 字典与 RBAC, 任一维缺口即拒绝; 与令牌自省层双维交集同源,
 * 取代已退役的 iam_client_policy 登录边界策略 (不新建规则表)。
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class AuthorizeIssuanceFilter extends OncePerRequestFilter {

    private static final AntPathRequestMatcher AUTHORIZE_MATCHER =
            new AntPathRequestMatcher("/oauth2/authorize");

    private final IssuanceAdmissionService issuanceAdmissionService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!AUTHORIZE_MATCHER.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // 未登录 / 匿名: 交给后续逻辑跳登录页, 不在发码前拦截
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }
        String clientId = request.getParameter("client_id");
        if (clientId == null || clientId.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }
        if (!issuanceAdmissionService.allowLogin(clientId, auth.getName())) {
            log.info("[签发准入] 拒绝签发授权码 (用户与客户端授权范围无交集): 客户端={}, 用户={}",
                    clientId, auth.getName());
            response.sendRedirect(request.getContextPath() + "/login.html?error=access_denied");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
