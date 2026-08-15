package net.xzh.authserver.security.token;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.userdetails.PortalUserDetailsService;

/**
 * Opaque Token 自省器: 资源服务器收到 Bearer token 后调本类 introspect().
 *
 * <p>access_token 已改为 Opaque 引用令牌 (随机短码), 资源服务器不再本地验签 JWT,
 * 而是到 Redis 查找对应的 OAuth2Authorization 授权记录:
 * <ul>
 *   <li>找不到 → token 已被撤销或不存在 → 抛异常 → 401</li>
 *   <li>已过期 → 抛异常 → 401</li>
 *   <li>access_token 已 invalidated (revoke 端点标记) → 抛异常 → 401</li>
 *   <li>有效 → 构造 OAuth2AuthenticatedPrincipal 返回 (含 sub/scope/roles)</li>
 * </ul>
 *
 * <p>撤销机制: /oauth2/revoke 调 save() 传入 invalidated=true,
 * RedisOAuth2AuthorizationService.save() 检测后直接 remove() 删 Redis key,
 * 下次 introspect 查不到即返回 401. 无需黑名单.</p>
 */
@Slf4j
@Component
public final class RedisOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    /** 资源服务器标识 (aud claim), 用于校验 token 的接收方. */
    private static final String CONTACTS_API_AUD = "contacts-api";

    /** Redis 持久化的 OAuth2Authorization 服务, 用于查找授权记录. */
    private final RedisOAuth2AuthorizationService authorizationService;
    /** 用户详情服务, 用于加载用户权限信息 (非 client_credentials 模式). */
    private final UserDetailsService portalUserDetailsService;
    /** 客户端仓库, 用于将授权记录的注册ID解析为对外 client_id. */
    private final RegisteredClientRepository clientRepository;

    public RedisOpaqueTokenIntrospector(
            RedisOAuth2AuthorizationService authorizationService,
            @Qualifier("portalUserDetailsService")
            UserDetailsService portalUserDetailsService,
            RegisteredClientRepository clientRepository) {
        this.authorizationService = authorizationService;
        this.portalUserDetailsService = portalUserDetailsService;
        this.clientRepository = clientRepository;
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
        Set<String> scopes = authorization.getAuthorizedScopes();

        // 解析对外 client_id (授权记录只存注册ID, 需经仓库还原为 client_id)
        String clientId = resolveClientId(authorization);

        // 构造 principal attributes (模拟 JWT 模式下的 claims 结构)
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", principalName);
        attributes.put("scope", String.join(" ", scopes));
        attributes.put("aud", List.of(CONTACTS_API_AUD));
        attributes.put("client_id", clientId);
        attributes.put("iss", "http://localhost:9000");
        if (authorization.getAuthorizationGrantType() != null) {
            // 授权类型: 资源中心据此区分「用户令牌」与「服务令牌 (client_credentials)」
            attributes.put("grant_type", authorization.getAuthorizationGrantType().getValue());
        }
        if (accessToken.getExpiresAt() != null) {
            attributes.put("exp", accessToken.getExpiresAt());
        }

        // 解析 roles: 通过 UserDetailsService 查 (client_credentials 模式无用户, roles 为空)
        Collection<GrantedAuthority> authorities = resolveAuthorities(principalName, scopes);

        log.debug("Opaque token introspect success, sub={}, scope={}", principalName, scopes);
        return new OpaquePrincipal(principalName, attributes, authorities);
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
     * 解析权限: 优先从 UserDetailsService 查 roles; client_credentials 模式无用户时,
     * 把 scope 转成 ROLE_ 前缀的权限 (便于 @PreAuthorize 统一处理).
     * <p>
     * V6.2: principal name 为业务用户编码 user_code, 需按 user_code 反查;
     * 兼容历史遗留令牌 (principal name 为用户名), 两者都失败才退回 scope 映射。
     */
    private Collection<GrantedAuthority> resolveAuthorities(String principalName, Set<String> scopes) {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        try {
            UserDetails user = null;
            if (portalUserDetailsService instanceof PortalUserDetailsService pus) {
                try {
                    user = pus.loadUserByUserCode(principalName);
                } catch (Exception ignored) {
                    // 历史令牌 principal=用户名, 继续按用户名加载
                }
            }
            if (user == null) {
                user = portalUserDetailsService.loadUserByUsername(principalName);
            }
            if (user != null) {
                user.getAuthorities().forEach(a -> authorities.add(new SimpleGrantedAuthority(a.getAuthority())));
                return authorities;
            }
        } catch (Exception e) {
            // client_credentials 模式 principalName=client_id, 查不到用户属正常
            log.debug("loadUserBy* 失败 (可能是 client_credentials), principal={}", principalName);
        }
        // 退而求其次: scope → ROLE_scope
        scopes.forEach(s -> authorities.add(new SimpleGrantedAuthority("ROLE_" + s.toUpperCase())));
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
