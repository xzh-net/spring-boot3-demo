package net.xzh.iam.resource.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.config.AuthServerProperties;
import net.xzh.iam.resource.service.EndpointPolicyService;
import net.xzh.iam.resource.service.EndpointPolicyService.Rule;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 表驱动接口准入路由器 (AuthorizationManager).
 * <p>
 * 三档模型 (资源链仅接管 /api/**):
 * <ul>
 *   <li><b>表内</b> (admin/portal/third 三域, 启动扫描播种): 按 required_authority 裁决
 *       (粗档常量或权限码), admin/portal 叠加客户端白名单闸;</li>
 *   <li><b>表外</b> (其余 /api/**): 走认证档 — 持有效内省令牌 (OAuth2AuthenticatedPrincipal)
 *       即放行, 匿名主体不算;</li>
 *   <li><b>/api/permitall/**}: 链层 permitAll, 不经本路由器。</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
public class EndpointAdmissionManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final EndpointPolicyService endpointPolicyService;
    private final AuthServerProperties authServerProperties;

    public EndpointAdmissionManager(EndpointPolicyService endpointPolicyService,
                                    AuthServerProperties authServerProperties) {
        this.endpointPolicyService = endpointPolicyService;
        this.authServerProperties = authServerProperties;
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

        boolean allowed = decide(rule, method, uri, auth) && clientWhitelistGate(rule, auth);
        log.debug("[Admission] {} {} -> {} ({}) = {}", method, uri, rule.requiredAuthority(), rule.domain(), allowed);
        return new AuthorizationDecision(allowed);
    }

    private boolean decide(Rule rule, String method, String uri, Authentication auth) {
        return switch (rule.requiredAuthority()) {
            case EndpointPolicyService.AUTH_PERMIT_ALL -> true;
            case EndpointPolicyService.AUTH_AUTHENTICATED -> authenticated(auth);
            default -> authenticated(auth) && hasAuthority(auth, rule.requiredAuthority());
        };
    }

    /**
     * 客户端白名单闸门 (对任意准入要求生效, 含 override):
     * <ul>
     *   <li>portal 域 — 令牌 client_id 须在门户白名单 ({@code authserver.portal-client-ids}),
     *       门户信息不对外任意开放;</li>
     *   <li>admin 域 — 令牌 client_id 须在管理白名单 ({@code authserver.admin-client-ids},
     *       如 admin-app), 原 adminApi 链 admin-client-ids 白名单语义,
     *       阶段 3 链合一后并入本闸门, 隔离非管理客户端碰管理接口
     *       (原 admin-m2m 管理 M2M 客户端已随跨服务调用退役);</li>
     *   <li>其它域 (含 third) 不设限.</li>
     * </ul>
     */
    private boolean clientWhitelistGate(Rule rule, Authentication auth) {
        String domain = rule.domain();
        Set<String> whitelist;
        if (EndpointPolicyService.DOMAIN_PORTAL.equals(domain)) {
            whitelist = authServerProperties.getPortalClientIds();
        } else if (EndpointPolicyService.DOMAIN_ADMIN.equals(domain)) {
            whitelist = authServerProperties.getAdminClientIds();
        } else {
            return true;
        }
        Object clientId = attributesOf(auth).get("client_id");
        boolean whitelisted = clientId != null && whitelist.contains(clientId.toString());
        if (!whitelisted) {
            log.warn("[Admission] {} 域被非白名单客户端访问: client_id={}", domain, clientId);
        }
        return whitelisted;
    }

    private boolean authenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated();
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        return auth.getAuthorities().stream().anyMatch(a -> authority.equals(a.getAuthority()));
    }

    /** 取令牌内省属性中的 client_id */
    private String clientIdOf(Authentication auth) {
        Object clientId = attributesOf(auth).get("client_id");
        return clientId == null ? null : clientId.toString();
    }

    private Map<String, Object> attributesOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
            return principal.getAttributes();
        }
        return Map.of();
    }
}