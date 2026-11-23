package net.xzh.iam.auth.security.token;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.iam.resource.service.PermissionService;
import net.xzh.iam.resource.service.ScopeService;

/**
 * Opaque Token 自省器: 资源服务器收到 Bearer token 后调本类 introspect().
 *
 * <p>access_token 已改为 Opaque 引用令牌 (随机短码), 资源服务器不再本地验签 JWT,
 * 而是到 Redis 查找对应的 OAuth2Authorization 授权记录:
 * <ul>
 *   <li>找不到 → token 已被撤销或不存在 → 抛异常 → 401</li>
 *   <li>已过期 → 抛异常 → 401</li>
 *   <li>access_token 已 invalidated (revoke 端点标记) → 抛异常 → 401</li>
 *   <li>有效 → 构造 OAuth2AuthenticatedPrincipal 返回 (含 sub/scope/authorities)</li>
 * </ul>
 *
 * <p>撤销机制: /oauth2/revoke 调 save() 传入 invalidated=true,
 * RedisOAuth2AuthorizationService.save() 检测后直接 remove() 删 Redis key,
 * 下次 introspect 查不到即返回 401. 无需黑名单.</p>
 *
 * <p><b>A-P2-4 单层收敛</b>: 原两层结构 (本类 UserDetails 路径取角色 +
 * {@code RbacAuthoritiesOpaqueTokenIntrospector} 追加角色与交集业务码) 已合并至本类 ——
 * 角色码与业务码一次算完 (角色查询从 2 次降为 1 次), authorities 唯一注入点,
 * 消费方: EndpointAdmissionManager (只认业务码, fail-closed) 与 /api 形式展示。</p>
 */
@Slf4j
@Component
public final class RedisOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** 资源服务器标识 (aud claim), 用于校验 token 的接收方. */
    private static final String CONTACTS_API_AUD = "contacts-api";

    /** Redis 持久化的 OAuth2Authorization 服务, 用于查找授权记录. */
    private final RedisOAuth2AuthorizationService authorizationService;
    /** 客户端仓库, 用于将授权记录的注册ID解析为对外 client_id. */
    private final RegisteredClientRepository clientRepository;
    /** OIDC 发行者标识, 与 AuthorizationServerSettings / id_token iss 同源. */
    private final String issuer;
    /** 角色/权限查询 (原 RBAC 层逻辑并入, A-P2-4). */
    private final PermissionService permissionService;
    /** 客户端 scope 展开 (双维交集的客户端维度, A-P2-4). */
    private final ScopeService scopeService;

    public RedisOpaqueTokenIntrospector(
            RedisOAuth2AuthorizationService authorizationService,
            RegisteredClientRepository clientRepository,
            @Value("${iam.issuer:http://localhost:9000}") String issuer,
            PermissionService permissionService,
            ScopeService scopeService) {
        this.authorizationService = authorizationService;
        this.clientRepository = clientRepository;
        this.issuer = issuer;
        this.permissionService = permissionService;
        this.scopeService = scopeService;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String tokenValue) {
        OAuth2Authorization authorization = authorizationService.findByToken(
                tokenValue, OAuth2TokenType.ACCESS_TOKEN);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_TOKEN,
                    "Token not found or already revoked",
                    null));
        }

        OAuth2Authorization.Token<OAuth2AccessToken> accessTokenWrapper = authorization.getAccessToken();
        if (accessTokenWrapper == null || accessTokenWrapper.getToken() == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_TOKEN,
                    "Access token missing",
                    null));
        }

        // 已被 revoke 端点标记为 invalidated
        if (accessTokenWrapper.isInvalidated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_TOKEN,
                    "Token has been revoked",
                    null));
        }

        OAuth2AccessToken accessToken = accessTokenWrapper.getToken();
        // 已过期
        if (accessToken.getExpiresAt() != null
                && Instant.now().isAfter(accessToken.getExpiresAt())) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_TOKEN,
                    "Token has expired",
                    null));
        }

        String principalName = authorization.getPrincipalName();

        // 解析对外 client_id (授权记录只存注册ID, 需经仓库还原为 client_id)
        String clientId = resolveClientId(authorization);

        // 【P0-1/P2-2 修复】scope 属性 = 注册表 scope (与 RFC 7662 claim 及实际授予同源),
        // 取代原 authorizedScopes (请求值)。消费方: /userinfo 的 profile/email claim 门控 (UserInfoController)。
        Set<String> scopes = resolveRegisteredScopes(authorization);

        // 构造 principal attributes (模拟 JWT 模式下的 claims 结构)
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", principalName);
        attributes.put("scope", String.join(" ", scopes));
        attributes.put("aud", List.of(CONTACTS_API_AUD));
        attributes.put("client_id", clientId);
        attributes.put("iss", issuer);
        if (authorization.getAuthorizationGrantType() != null) {
            // 授权类型: 资源中心据此区分「用户令牌」与「服务令牌 (client_credentials)」
            attributes.put("grant_type", authorization.getAuthorizationGrantType().getValue());
        }
        if (accessToken.getExpiresAt() != null) {
            attributes.put("exp", accessToken.getExpiresAt());
        }

        // 权限单点计算 (A-P2-4): 角色码 + 双维交集业务码一次算完
        Collection<GrantedAuthority> authorities = resolveAuthorities(principalName, clientId);

        log.debug("Opaque token introspect success, sub={}, scope={}", principalName, scopes);
        return new OpaquePrincipal(principalName, attributes, authorities);
    }

    /**
     * 注册表 scope = 客户端配置的授权范围 (oauth2_registered_client.scopes)。
     * P0-1/P2-2: scope 语义统一为「配置值」——与 RFC 7662 内省 claim、业务码授予同源。
     * 仓库查询失败时退回授权记录值, 保证属性非空。
     */
    private Set<String> resolveRegisteredScopes(OAuth2Authorization authorization) {
        try {
            RegisteredClient client = clientRepository.findById(authorization.getRegisteredClientId());
            if (client != null && client.getScopes() != null && !client.getScopes().isEmpty()) {
                return client.getScopes();
            }
        } catch (Exception e) {
            log.warn("读取注册表 scope 失败, 退回授权记录值: {}", authorization.getRegisteredClientId());
        }
        return authorization.getAuthorizedScopes();
    }

    /**
     * 将授权记录的注册客户端ID还原为对外 client_id.
     * 仓库查询失败时退回注册ID, 保证属性非空.
     */
    private String resolveClientId(OAuth2Authorization authorization) {
        String registeredId = authorization.getRegisteredClientId();
        try {
            RegisteredClient client = clientRepository.findById(registeredId);
            if (client != null) {
                return client.getClientId();
            }
        } catch (Exception e) {
            log.warn("解析 client_id 失败, 退回注册ID: {}", registeredId);
        }
        return registeredId;
    }

    /**
     * 权限解析 (A-P2-4 单层收敛后的唯一注入点): 角色码 + 双维交集业务码.
     * <p>
     * 原两层结构 (本类经 UserDetails 取角色 + RbacAuthoritiesOpaqueTokenIntrospector 追加
     * 角色与交集码) 合并于此, 角色查询从 2 次降为 1 次, authorities 只在本方法产生:
     * <ul>
     *   <li><b>角色码</b>: sub (user_code) → sys_user_role → sys_role, 原样注入 (查不到为空);</li>
     *   <li><b>业务码 (双维交集, fail-closed)</b> = 用户 RBAC 码 ∩ 客户端 scope 展开码:
     *       用户有码、客户端 scope 未含 → 不注入, 反之亦然; 客户端无业务 scope → 一码不放;</li>
     * </ul>
     * 用户不存在 (已删除/历史用户名 token) → 角色与业务码皆空 → 端点准入拒绝 (fail-closed 语义与原两层一致).
     * 权限查询异常向上抛出 → 自省失败 401 (与原外层行为一致, 不吞).
     */
    private Collection<GrantedAuthority> resolveAuthorities(String principalName, String clientId) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        List<String> roleCodes = permissionService.findRoleCodes(principalName);
        for (String role : roleCodes) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        Set<String> clientCodes = scopeService.resolveClientBusinessCodes(clientId);
        Set<String> userCodes = permissionService.findPermissions(principalName);
        Set<String> grantedCodes = new LinkedHashSet<>();
        for (String permission : userCodes) {
            if (clientCodes.contains(permission)) {
                grantedCodes.add(permission);
                authorities.add(new SimpleGrantedAuthority(permission));
            }
        }
        log.debug("[Introspect] 单层权限解析, sub={}, roles={}, client={}, userCodes={}, scopeCodes={}, 交集注入={}",
                principalName, roleCodes, clientId, userCodes, clientCodes, grantedCodes);
        return authorities;
    }

    /**
     * 简单的 OAuth2AuthenticatedPrincipal 实现.
     * 不继承 AbstractAuthenticationToken 以避免 eraseCredentials 递归导致的 StackOverflowError.
     */
    private static class OpaquePrincipal implements OAuth2AuthenticatedPrincipal {

        private final String name;
        private final Map<String, Object> attributes;
        private final Collection<GrantedAuthority> authorities;

        OpaquePrincipal(String name, Map<String, Object> attributes,
                        Collection<GrantedAuthority> authorities) {
            this.name = name;
            this.attributes = Map.copyOf(attributes);
            this.authorities = List.copyOf(authorities);
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Map<String, Object> getAttributes() {
            return attributes;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }
    }
}
