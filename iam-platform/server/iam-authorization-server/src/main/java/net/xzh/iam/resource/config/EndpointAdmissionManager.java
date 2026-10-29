package net.xzh.iam.resource.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.EndpointPolicyService;
import net.xzh.iam.resource.service.EndpointPolicyService.Rule;

import java.util.List;

/**
 * 表驱动接口准入路由器 (AuthorizationManager).
 * <p>
 * 三档模型 (资源链仅接管三前缀):
 * <ul>
 *   <li><b>表内</b> (admin/portal/third 三域, 启动扫描播种): 按 required_authority 裁决
 *       (全部为权限码, 粗档常量已退役)。客户端维度隔离由令牌双维交集承担, 无独立白名单闸;</li>
 *   <li><b>表外</b> (三前缀其余端点): 走认证档 — 持有效内省令牌 (OAuth2AuthenticatedPrincipal)
 *       即放行, 匿名主体不算;</li>
 *   <li><b>/permitall/**}: 链层 permitAll, 不经本路由器。</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
public class EndpointAdmissionManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final EndpointPolicyService endpointPolicyService;

    public EndpointAdmissionManager(EndpointPolicyService endpointPolicyService) {
        this.endpointPolicyService = endpointPolicyService;
    }

    @Override
    public AuthorizationDecision check(java.util.function.Supplier<Authentication> authenticationSupplier,
                                       RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        Authentication auth = authenticationSupplier.get();

        Rule rule = endpointPolicyService.findRule(method, uri);
        if (rule == null) {
            // 表外走认证档: 有效内省令牌 (真实主体) 即放行; AnonymousAuthenticationToken 不算
            boolean allowed = auth != null && auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal;
            log.debug("[Admission] 未登记准入点, 走认证档 {} {} -> {}", method, uri, allowed);
            return new AuthorizationDecision(allowed);
        }

        if (!rule.enabled()) {
            // status=0 停用行: 准入直接拒绝 (deny), 不再降级认证档
            log.warn("[Admission] 端点已停用(拒绝) {} {} ({})", method, uri, rule.path());
            return new AuthorizationDecision(false);
        }

        boolean allowed = decide(rule, method, uri, auth);
        log.debug("[Admission] {} {} -> {} = {}", method, uri, rule.requiredAuthority(), allowed);
        return new AuthorizationDecision(allowed);
    }

    private boolean decide(Rule rule, String method, String uri, Authentication auth) {
        return switch (rule.requiredAuthority()) {
            case EndpointPolicyService.AUTH_PERMIT_ALL -> true;
            case EndpointPolicyService.AUTH_AUTHENTICATED -> authenticated(auth);
            default -> authenticated(auth) && hasAuthority(auth, rule.requiredAuthority());
        };
    }

    private boolean authenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated();
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        return auth.getAuthorities().stream().anyMatch(a -> authority.equals(a.getAuthority()));
    }
}