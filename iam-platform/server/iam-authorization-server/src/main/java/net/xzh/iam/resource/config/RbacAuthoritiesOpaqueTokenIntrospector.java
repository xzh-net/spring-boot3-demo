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
import net.xzh.iam.auth.security.token.RedisOpaqueTokenIntrospector;
import net.xzh.iam.resource.service.PermissionService;
import net.xzh.iam.resource.service.ScopeService;

/**
 * RBAC + Scope 双维增强型 Opaque Token 自省器 (单服务本地内省).
 * <p>
 * 委托同进程 {@link RedisOpaqueTokenIntrospector} 完成 token 校验 (Redis 查授权记录,
 * 不再 HTTP 自回环调 /oauth2/introspect)。令牌 authorities 由两部分构成:
 * <ul>
 *   <li><b>业务角色码</b>: sub (user_code) → sys_user_role → sys_role, 角色编码原样注入;</li>
 *   <li><b>业务权限码 (双维交集, fail-closed)</b> = 用户 RBAC 码 ∩ 客户端 scope 展开码:
 *       <ul>
 *         <li>用户码: sub → sys_user_role → sys_role → sys_role_permission → sys_permission (启用态, 细粒度);</li>
 *         <li>客户端码: client_id → oauth2_registered_client.scopes → sys_scope (启用态)
 *              → sys_scope_permission → sys_permission (启用态, 见 {@link ScopeService});</li>
 *         <li>用户有码、客户端 scope 未含 → 不注入 (403), 反之亦然; 客户端无业务 scope → 一码不放;</li>
 *       </ul>
 * </ul>
 * 粗档常量 (ADMIN_SERVICE_TOKEN / PORTAL_SERVICE_TOKEN) 与 M2M 服务令牌分支已退役:
 * 端点准入全部按权限码裁决 (见 EndpointAdmissionManager), 客户端维度隔离由 scope 交集承担。
 */
@Slf4j
@Component
public class RbacAuthoritiesOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final RedisOpaqueTokenIntrospector delegate;
    private final PermissionService permissionService;
    private final ScopeService scopeService;

    public RbacAuthoritiesOpaqueTokenIntrospector(
            RedisOpaqueTokenIntrospector delegate,
            PermissionService permissionService,
            ScopeService scopeService) {
        this.delegate = delegate;
        this.permissionService = permissionService;
        this.scopeService = scopeService;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
        String userCode = principal.getName();
        if (!StringUtils.hasText(userCode)) {
            return principal;
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(principal.getAuthorities());
        // 业务角色码: 依据 sub (user_code) 解析本地业务 RBAC (无影子用户表), 角色编码原样注入
        List<String> roleCodes = permissionService.findRoleCodes(userCode);
        for (String role : roleCodes) {
            authorities.add(new SimpleGrantedAuthority(role));
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

        return new EnrichedPrincipal(principal, authorities);
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