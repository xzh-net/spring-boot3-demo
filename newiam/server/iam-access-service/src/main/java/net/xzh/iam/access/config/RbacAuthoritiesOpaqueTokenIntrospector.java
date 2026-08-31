package net.xzh.iam.access.config;

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
import net.xzh.iam.access.service.PermissionService;

/**
 * RBAC 增强型 Opaque Token 自省器.
 * <p>
 * 委托认证中心 /oauth2/introspect 校验 token 后, 依据 <b>grant_type 与 client_id</b> 判定令牌身份,
 * 而非「本地查不到用户」反推 (用户可能仅存在于 iam_identity, 资源中心未同步 D9):
 * <ul>
 *   <li><b>服务令牌</b> (client_credentials, 或 client_id ∈ {@code authserver.service-client-ids} 兜底):
 *       注入 {@code PORTAL_SERVICE_TOKEN} (门户服务凭证); <b>internal 域另有硬规则</b>
 *       (仅认证中心 resource-server 可调, 见 EndpointAdmissionManager, 不受本托底名单影响);
 *       其中 client_id ∈ {@code authserver.admin-m2m-client-ids} (默认 admin-m2m) 的
 *       <b>管理 M2M</b> 服务令牌改注入 {@code ADMIN_SERVICE_TOKEN} (管理服务凭证),
 *       供认证中心以机器身份执行管理写 (如删除用户联动清理);</li>
 *   <li><b>门户应用客户端</b> (client_id ∈ {@code authserver.portal-client-ids} 白名单, 如 portal-app) 签发的
 *       <b>用户令牌</b>: 在注入业务 RBAC 之外追加 {@code PORTAL_SERVICE_TOKEN},
 *       作为 portal 域 (/api/public/**) 的门票, 门户信息不对任意客户端开放;</li>
 *   <li><b>其它用户令牌</b>: 依据 sub (业务用户编码 user_code) 解析本地业务 RBAC
 *       (iam_authorization.sys_user_role → sys_role → sys_permission),
 *       注入各业务角色编码与权限编码 authorities; 业务角色含 {@code ADMIN} 时额外注入
 *       {@code ADMIN_SERVICE_TOKEN} (管理服务凭证) 供管理接口准入鉴权;
 *       (V6.2: 影子用户表 sys_user 已删除, 用户权威在认证中心 iam_identity.sys_user)</li>
 * </ul>
 */
@Slf4j
@Component
public class RbacAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** 服务账户/门户应用标识: grant_type=client_credentials、service-client-ids 白名单或 portal-client-ids 白名单触发 */
    private static final String PORTAL_SERVICE_TOKEN = "PORTAL_SERVICE_TOKEN";

    /** 管理端业务角色编码 (sys_role.role_code), 命中则令牌类别为管理服务凭证 */
    private static final String ADMIN_ROLE_CODE = "ADMIN";

    /** 管理服务凭证标识: 用户令牌持有者具备管理端角色时注入; 管理 M2M (admin-m2m) 服务令牌也注入 */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    /** 授权类型标识: client_credentials (RFC 6749 §4.4), 内省 attributes 由认证中心注入 */
    private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";

    private final NimbusOpaqueTokenIntrospector delegate;
    private final PermissionService permissionService;
    private final Set<String> serviceClientIds;
    private final Set<String> portalClientIds;
    private final Set<String> adminM2mClientIds;

    public RbacAuthoritiesOpaqueTokenIntrospector(
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}") String introspectionUri,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}") String clientId,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}") String clientSecret,
            PermissionService permissionService,
            AuthServerProperties authServerProperties) {
        this.delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
        this.permissionService = permissionService;
        this.serviceClientIds = authServerProperties.getServiceClientIds();
        this.portalClientIds = authServerProperties.getPortalClientIds();
        this.adminM2mClientIds = authServerProperties.getAdminM2mClientIds();
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
            if (isAdminM2mClient(principal)) {
                // 管理 M2M 服务令牌 (client_id ∈ admin-m2m-client-ids):
                // 认证中心以机器身份执行管理写, 注入 ADMIN_SERVICE_TOKEN (管理服务凭证)
                authorities.add(new SimpleGrantedAuthority(ADMIN_SERVICE_TOKEN));
                log.debug("[Introspect] 管理 M2M 服务令牌注入 ADMIN_SERVICE_TOKEN, sub={}", userCode);
            } else {
                // 服务令牌: client_credentials 或白名单内客户端 → PORTAL_SERVICE_TOKEN (M2M)
                authorities.add(new SimpleGrantedAuthority(PORTAL_SERVICE_TOKEN));
                log.debug("[Introspect] 服务令牌注入 PORTAL_SERVICE_TOKEN, sub={}", userCode);
            }
        } else {
            // 用户令牌: 依据 sub (user_code) 解析本地业务 RBAC (无影子用户表)
            // 令牌类别: 业务角色含 ADMIN → 管理服务凭证; 业务角色码原样注入 (不再拼 ROLE_ 前缀)
            List<String> roleCodes = permissionService.findRoleCodes(userCode);
            for (String role : roleCodes) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
            if (roleCodes.contains(ADMIN_ROLE_CODE)) {
                authorities.add(new SimpleGrantedAuthority(ADMIN_SERVICE_TOKEN));
            }
            if (isPortalClient(principal)) {
                // 门户应用客户端签发的用户令牌: 追加门户服务凭证 (portal 域门票),
                // 门户信息仅限门户客户端访问
                authorities.add(new SimpleGrantedAuthority(PORTAL_SERVICE_TOKEN));
            }
            for (String permission : permissionService.findPermissions(userCode)) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
            log.debug("[Introspect] 用户令牌注入 RBAC authorities, sub={}, roles={}",
                    userCode, roleCodes);
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

    /** 判定是否为门户应用客户端签发 (client_id ∈ portal-client-ids 白名单) */
    private boolean isPortalClient(OAuth2AuthenticatedPrincipal principal) {
        Object clientId = principal.getAttributes().get("client_id");
        return clientId != null && portalClientIds.contains(clientId.toString());
    }

    /** 判定是否为管理 M2M 客户端签发 (client_id ∈ admin-m2m-client-ids 白名单) */
    private boolean isAdminM2mClient(OAuth2AuthenticatedPrincipal principal) {
        Object clientId = principal.getAttributes().get("client_id");
        return clientId != null && adminM2mClientIds.contains(clientId.toString());
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