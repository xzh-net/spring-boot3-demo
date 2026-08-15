package net.xzh.authserver.security.web;

import java.io.IOException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.ClientUserPolicyService;

/**
 * 授权端点 (发码) 准入过滤器.
 * <p>
 * 在 {@code /oauth2/authorize} 签发授权码之前先做"客户端 × 身份类型"校验:
 * 已登录用户向配置了策略的客户端申请授权码时, 身份类型不在允许集合内则直接
 * 302 回认证中心登录页 {@code /login.html?error} (与密码错误的失败体验一致),
 * 不向客户端下发授权码。令牌签发阶段的二次校验由
 * {@code PolicyAware*} 提供者负责。
 */
@Slf4j
public class AuthorizePolicyFilter extends OncePerRequestFilter {

    private static final AntPathRequestMatcher AUTHORIZE_MATCHER =
            new AntPathRequestMatcher("/oauth2/authorize");

    private final ClientUserPolicyService clientUserPolicyService;

    public AuthorizePolicyFilter(ClientUserPolicyService clientUserPolicyService) {
        this.clientUserPolicyService = clientUserPolicyService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!AUTHORIZE_MATCHER.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // 未登录 / 匿名: 交给后续逻辑跳登录页, 不在发码阶段拦截
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }
        String clientId = request.getParameter("client_id");
        if (clientId == null || clientId.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            clientUserPolicyService.check(clientId, auth.getName());
        } catch (OAuth2AuthenticationException e) {
            log.info("[发码准入] 拒绝签发授权码: 客户端={}, 用户={}: {}", clientId, auth.getName(), e.getMessage());
            response.sendRedirect(request.getContextPath() + "/login.html?error");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
