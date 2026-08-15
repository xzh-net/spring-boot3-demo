package net.xzh.resource.config;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.service.PermissionService;

/**
 * RBAC 增强型 Opaque Token 自省器.
 * <p>
 * 委托认证中心 /oauth2/introspect 校验 token 后, 依据 <b>grant_type 与 client_id</b> 判定令牌身份,
 * 而非「本地查不到用户」反推 (用户可能仅存在于 iam_identity, 资源中心未同步 D9):
 * <ul>
 *   <li><b>服务令牌</b> (client_credentials, 或 client_id ∈ {@code authserver.service-client-ids} 白名单):
 *       注入 {@code ROLE_SERVICE}, 供内部接口 {@code hasRole('SERVICE')} 鉴权, 禁止普通用户访问;</li>
 *   <li><b>用户令牌</b>: 依据 sub (业务用户编码 user_code) 解析本地业务 RBAC
 *       (iam_authorization.sys_user_role → sys_role → sys_permission),
 *       注入 {@code ROLE_<角色编码>} 与权限编码 authorities, 供
 *       {@code @PreAuthorize("hasRole('ADMIN')")} 等方法级鉴权使用;
 *       (V6.2: 影子用户表 sys_user 已删除, 用户权威在认证中心 iam_identity.sys_user)</li>
 * </ul>
 */
@Slf4j
@Component
public class RbacAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** 服务账户标识: 由 grant_type=client_credentials 或 service-client-ids 白名单触发 */
    private static final String SERVICE_ROLE = "ROLE_SERVICE";

    /** 授权类型标识: client_credentials (RFC 6749 §4.4), 内省 attributes 由认证中心注入 */
    private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";

    private final NimbusOpaqueTokenIntrospector delegate;
    private final PermissionService permissionService;
    private final Set<String> serviceClientIds;

    public RbacAuthoritiesOpaqueTokenIntrospector(
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}") String introspectionUri,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}") String clientId,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}") String clientSecret,
            PermissionService permissionService,
            AuthServerProperties authServerProperties) {
        this.delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
        this.permissionService = permissionService;
        this.serviceClientIds = authServerProperties.getServiceClientIds();
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
        String userCode = principal.getName();
        if (!StringUtils.hasText(userCode)) {
            return principal;
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(principal.getAuthorities());
        if (isServiceToken(principal)) {
            // 服务令牌: client_credentials 或白名单内客户端 → ROLE_SERVICE (M2M)
            authorities.add(new SimpleGrantedAuthority(SERVICE_ROLE));
            log.debug("[Introspect] 服务令牌注入 ROLE_SERVICE, sub={}", userCode);
        } else {
            // 用户令牌: 依据 sub (user_code) 解析本地业务 RBAC (无影子用户表)
            for (String role : permissionService.findRoleCodes(userCode)) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
            for (String permission : permissionService.findPermissions(userCode)) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
            log.debug("[Introspect] 用户令牌注入 RBAC authorities, sub={}, roles={}",
                    userCode, permissionService.findRoleCodes(userCode));
        }

        return new EnrichedPrincipal(principal, authorities);
    }

    /**
     * 判定是否为服务令牌 (M2M): grant_type=client_credentials 或在 service-client-ids 白名单内。
     * 依据令牌自身属性, 不依赖本地用户表。
     */
    private boolean isServiceToken(OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> attributes = principal.getAttributes();
        Object grantType = attributes.get("grant_type");
        if (GRANT_CLIENT_CREDENTIALS.equals(grantType)) {
            return true;
        }
        Object clientId = attributes.get("client_id");
        return clientId != null && serviceClientIds.contains(clientId.toString());
    }

    /** 保留原始属性, 覆写 authorities 的 principal 包装 */
    private static final class EnrichedPrincipal implements OAuth2AuthenticatedPrincipal {

        private final OAuth2AuthenticatedPrincipal delegate;
        private final Collection<GrantedAuthority> authorities;

        EnrichedPrincipal(OAuth2AuthenticatedPrincipal delegate, Collection<GrantedAuthority> authorities) {
            this.delegate = delegate;
            this.authorities = List.copyOf(authorities);
        }

        @Override
        public String getName() {
            return delegate.getName();
        }

        @Override
        public Map<String, Object> getAttributes() {
            return delegate.getAttributes();
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }
    }
}