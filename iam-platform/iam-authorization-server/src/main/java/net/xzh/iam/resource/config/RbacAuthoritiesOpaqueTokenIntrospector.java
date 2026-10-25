package net.xzh.iam.resource.config;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.config.AuthServerProperties;
import net.xzh.iam.auth.security.token.RedisOpaqueTokenIntrospector;
import net.xzh.iam.resource.service.PermissionService;
import net.xzh.iam.resource.service.ScopeService;

/**
 * RBAC + Scope 双维增强型 Opaque Token 自省器 (单服务本地内省).
 * <p>
 * 委托同进程 {@link RedisOpaqueTokenIntrospector} 完成 token 校验 (Redis 查授权记录,
 * 不再 HTTP 自回环调 /oauth2/introspect), 依据 <b>grant_type 与 client_id</b> 判定令牌身份,
 * 而非「本地查不到用户」反推:
 * <ul>
 *   <li><b>服务令牌</b> (client_credentials, 或 client_id ∈ {@code authserver.service-client-ids} 兜底):
 *       注入 {@code PORTAL_SERVICE_TOKEN} (门户服务凭证), M2M 无用户维度;</li>
 *   <li><b>用户令牌</b>: 业务权限码注入 = <b>用户 RBAC 码 ∩ 客户端 scope 展开码</b> (双维交集, fail-closed):
 *       <ul>
 *         <li>用户码: sub (user_code) → sys_user_role → sys_role → sys_role_permission → sys_permission (启用态, 细粒度);</li>
 *         <li>客户端码: client_id → oauth2_registered_client.scopes → sys_scope (启用态)
 *              → sys_scope_permission → sys_permission (启用态, 粗粒度, 见 {@link ScopeService});</li>
 *         <li>用户有码、客户端 scope 未含 → 不注入 (403), 反之亦然;</li>
 *       </ul>
 *       业务码之外: 业务角色含 {@code ADMIN} 时注入 {@code ADMIN_SERVICE_TOKEN} (通道粗档),
 *       门户客户端令牌追加 {@code PORTAL_SERVICE_TOKEN} (portal 域门票), 业务角色码原样注入;</li>
 *   <li>端点裁决不变: {@code iam_endpoint_policy.required_authority} ∈ 上述 authorities (见 EndpointAdmissionManager)。</li>
 * </ul>
 */
@Slf4j
@Component
public class RbacAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** 服务账户/门户应用标识: grant_type=client_credentials、service-client-ids 白名单或 portal-client-ids 白名单触发 */
    private static final String PORTAL_SERVICE_TOKEN = "PORTAL_SERVICE_TOKEN";

    /** 管理端业务角色编码 (sys_role.role_code), 命中则令牌类别为管理服务凭证 */
    private static final String ADMIN_ROLE_CODE = "ADMIN";

    /** 管理服务凭证标识: 用户令牌持有者具备管理端角色时注入 */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    /** 授权类型标识: client_credentials (RFC 6749 §4.4), 内省 attributes 由认证中心注入 */
    private static final String GRANT_CLIENT_CREDENTIALS = "client_credentials";

    private final RedisOpaqueTokenIntrospector delegate;
    private final PermissionService permissionService;
    private final ScopeService scopeService;
    private final Set<String> serviceClientIds;
    private final Set<String> portalClientIds;

    public RbacAuthoritiesOpaqueTokenIntrospector(
            RedisOpaqueTokenIntrospector delegate,
            PermissionService permissionService,
            ScopeService scopeService,
            AuthServerProperties authServerProperties) {
        this.delegate = delegate;
        this.permissionService = permissionService;
        this.scopeService = scopeService;
        this.serviceClientIds = authServerProperties.getServiceClientIds();
        this.portalClientIds = authServerProperties.getPortalClientIds();
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
            // 服务令牌: 一律注入 PORTAL_SERVICE_TOKEN (M2M) — 原 admin-m2m 管理 M2M 通道
            // 已随跨服务调用退役 (阶段清理), 管理 API 仅对管理员用户令牌开放
            authorities.add(new SimpleGrantedAuthority(PORTAL_SERVICE_TOKEN));
            log.debug("[Introspect] 服务令牌注入 PORTAL_SERVICE_TOKEN, sub={}", userCode);
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
            // ★ 双维交集 (核心): 业务码 = 用户 RBAC 码 ∩ 客户端 scope 展开码
            // 用户有码、客户端 scope 未含 → 不注入; 反之亦不注入; 客户端无业务 scope → fail-closed 一码不放
            String clientId = clientIdOf(principal);
            Set<String> clientCodes = scopeService.resolveClientBusinessCodes(clientId);
            Set<String> userCodes = permissionService.findPermissions(userCode);
            Set<String> grantedCodes = new LinkedHashSet<>();
            for (String permission : userCodes) {
                if (clientCodes.contains(permission)) {
                    grantedCodes.add(permission);
                    authorities.add(new SimpleGrantedAuthority(permission));
                }
            }
            log.debug("[Introspect] 用户令牌双维裁决, sub={}, roles={}, client={}, userCodes={}, scopeCodes={}, 交集注入={}",
                    userCode, roleCodes, clientId, userCodes, clientCodes, grantedCodes);
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

    /** 取令牌内省属性中的 client_id (无则 null → scope 展开 fail-closed) */
    private String clientIdOf(OAuth2AuthenticatedPrincipal principal) {
        Object clientId = principal.getAttributes().get("client_id");
        return clientId == null ? null : clientId.toString();
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