package net.xzh.iam.auth.security.web;

import java.io.IOException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.LoginAdmissionService;

/**
 * 授权端点签发准入过滤器 (登录维度: client_login_policy 准入表裁决).
 * <p>
 * 在 {@code /oauth2/authorize} 签发授权码之前先做「该用户能否登录该客户端」判定,
 * 判据为 {@link LoginAdmissionService} 查 client_login_policy 准入表 (allow-list,
 * fail-closed): 不合规直接 302 回登录页 {@code /login.html?error=access_denied}
 * (与密码错误的失败体验一致, 提示语区分), 不向客户端下发授权码。
 * <p>
 * <b>【已启用】</b>准入判定按 client_login_policy 准入表实时裁决 (2026-11-04 启用):
 * 未命中即 302 拒发授权码, fail-closed。与授权维度解耦 — 登录资格只看准入表,
 * 令牌业务码仍由自省层 用户码 ∩ scope码 决定 (见 {@code RbacAuthoritiesOpaqueTokenIntrospector}),
 * 改权限码不再影响登录边界。
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class AuthorizeIssuanceFilter extends OncePerRequestFilter {

    private static final AntPathRequestMatcher AUTHORIZE_MATCHER =
            new AntPathRequestMatcher("/oauth2/authorize");

    private final LoginAdmissionService loginAdmissionService;

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
        // 【登录层】准入表裁决 (client_login_policy): 未命中 → 302 拒发授权码, fail-closed
        if (!loginAdmissionService.canLogin(clientId, auth.getName())) {
            log.info("[签发准入] 拒绝签发授权码 (准入表未命中): 客户端={}, 用户={}",
                    clientId, auth.getName());
            response.sendRedirect(request.getContextPath() + "/login.html?error=access_denied");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
