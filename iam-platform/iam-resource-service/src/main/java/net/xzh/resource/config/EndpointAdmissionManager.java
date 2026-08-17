package net.xzh.resource.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.entity.IamEndpointPolicy;
import net.xzh.resource.service.CapabilityService;
import net.xzh.resource.service.CapabilityService.Admission;
import net.xzh.resource.service.EndpointPolicyService;
import net.xzh.resource.service.EndpointPolicyService.Rule;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 表驱动接口准入路由器 (AuthorizationManager).
 * <p>
 * 取代 ResourceServerConfig 中写死的 4 条 security 规则: 每条请求按 method+path 匹配
 * iam_endpoint_policy 启用规则, 依据 required_authority 裁决;
 * 未命中规则默认拒绝 (deny-by-default)。
 * <ul>
 *   <li><b>internal 域为硬规则</b>: 不进入规则表、不支持配置, 仅认证中心 M2M
 *       ({@value #IDENTITY_PROVIDER_CLIENT_ID}) 可调 (服务间角色内省, 外界无到达路线);</li>
 *   <li>portal 域叠加 client_id 门户白名单 (门户信息仅限指定客户端);</li>
 *   <li>capability 域委托 {@link CapabilityService} 做能力订阅校验。</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
public class EndpointAdmissionManager implements AuthorizationManager<RequestAuthorizationContext> {

    /** 认证中心服务客户端 (M2M): internal 域仅允许该 client_id 调用 (硬规则, 不可配置) */
    private static final String IDENTITY_PROVIDER_CLIENT_ID = "resource-server";

    /** internal 域路径前缀: 硬规则直接裁决, 不进入 iam_endpoint_policy 规则表 */
    private static final String INTERNAL_PATH_PREFIX = "/api/internal/";

    private final EndpointPolicyService endpointPolicyService;
    private final CapabilityService capabilityService;
    private final AuthServerProperties authServerProperties;

    public EndpointAdmissionManager(EndpointPolicyService endpointPolicyService,
                                    CapabilityService capabilityService,
                                    AuthServerProperties authServerProperties) {
        this.endpointPolicyService = endpointPolicyService;
        this.capabilityService = capabilityService;
        this.authServerProperties = authServerProperties;
    }

    @Override
    public AuthorizationDecision check(java.util.function.Supplier<Authentication> authenticationSupplier,
                                       RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        Authentication auth = authenticationSupplier.get();

        // internal 域硬规则: 仅认证中心 M2M (resource-server) 可调, 不进入规则表、不支持配置
        if (uri.startsWith(INTERNAL_PATH_PREFIX)) {
            boolean allowed = authenticated(auth) && hasAuthority(auth, IamEndpointPolicy.AUTH_PORTAL_SERVICE_TOKEN)
                    && IDENTITY_PROVIDER_CLIENT_ID.equals(clientIdOf(auth));
            log.debug("[Admission] internal 域硬规则 {} {} -> 仅认证中心({}) = {}", method, uri,
                    IDENTITY_PROVIDER_CLIENT_ID, allowed);
            return new AuthorizationDecision(allowed);
        }

        Rule rule = endpointPolicyService.findRule(method, uri);
        if (rule == null) {
            log.debug("[Admission] 未登记准入点, 默认拒绝: {} {}", method, uri);
            return new AuthorizationDecision(false);
        }

        boolean allowed = decide(rule, method, uri, auth) && clientWhitelistGate(rule, auth);
        log.debug("[Admission] {} {} -> {} ({}) = {}", method, uri, rule.requiredAuthority(), rule.domain(), allowed);
        return new AuthorizationDecision(allowed);
    }

    private boolean decide(Rule rule, String method, String uri, Authentication auth) {
        return switch (rule.requiredAuthority()) {
            case IamEndpointPolicy.AUTH_PERMIT_ALL -> true;
            case IamEndpointPolicy.AUTH_AUTHENTICATED -> authenticated(auth);
            case IamEndpointPolicy.AUTH_CAPABILITY ->
                    authenticated(auth) && admitCapability(method, uri, auth);
            default -> authenticated(auth) && hasAuthority(auth, rule.requiredAuthority());
        };
    }

    private boolean admitCapability(String method, String uri, Authentication auth) {
        Map<String, Object> attributes = attributesOf(auth);
        Admission admission = capabilityService.admit(method, uri, attributes, scopesOf(auth));
        log.debug("[Admission] 能力准入 {} {} -> {}", method, uri, admission);
        return admission == Admission.ALLOWED;
    }

    /**
     * 门户域客户端白名单闸门 (对任意准入要求生效, 含 override):
     * <ul>
     *   <li>portal 域 — 令牌 client_id 须在门户白名单 ({@code authserver.portal-client-ids}),
     *       门户信息不对外任意开放;</li>
     *   <li>internal 域为硬规则 (仅认证中心 M2M), 在 {@link #check} 中前置裁决,
     *       不走本闸门亦不进规则表;</li>
     *   <li>其它域不设限.</li>
     * </ul>
     */
    private boolean clientWhitelistGate(Rule rule, Authentication auth) {
        String domain = rule.domain();
        if (!IamEndpointPolicy.DOMAIN_PORTAL.equals(domain)) {
            return true;
        }
        Object clientId = attributesOf(auth).get("client_id");
        boolean whitelisted = clientId != null
                && authServerProperties.getPortalClientIds().contains(clientId.toString());
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

    /** 组装令牌 scopes: SCOPE_* authorities + 内省属性 scope claim */
    private Collection<String> scopesOf(Authentication auth) {
        List<String> scopes = new ArrayList<>();
        if (auth != null) {
            for (GrantedAuthority authority : auth.getAuthorities()) {
                if (authority.getAuthority().startsWith("SCOPE_")) {
                    scopes.add(authority.getAuthority().substring("SCOPE_".length()));
                }
            }
            Object scopeClaim = attributesOf(auth).get("scope");
            if (scopeClaim instanceof Collection<?> list) {
                list.forEach(o -> scopes.add(String.valueOf(o)));
            } else if (scopeClaim != null) {
                for (String s : String.valueOf(scopeClaim).split(",")) {
                    if (!s.isBlank()) {
                        scopes.add(s.trim());
                    }
                }
            }
        }
        return scopes;
    }
}