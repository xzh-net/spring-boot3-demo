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
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;

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
public class RedisOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private static final String CONTACTS_API_AUD = "contacts-api";

    private final RedisOAuth2AuthorizationService authorizationService;
    private final UserDetailsService portalUserDetailsService;

    public RedisOpaqueTokenIntrospector(
            RedisOAuth2AuthorizationService authorizationService,
            @Qualifier("portalUserDetailsService")
            UserDetailsService portalUserDetailsService) {
        this.authorizationService = authorizationService;
        this.portalUserDetailsService = portalUserDetailsService;
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

        // 构造 principal attributes (模拟 JWT 模式下的 claims 结构)
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", principalName);
        attributes.put("scope", String.join(" ", scopes));
        attributes.put("aud", List.of(CONTACTS_API_AUD));
        attributes.put("client_id", authorization.getRegisteredClientId());
        attributes.put("iss", "http://localhost:9000");
        if (accessToken.getExpiresAt() != null) {
            attributes.put("exp", accessToken.getExpiresAt());
        }

        // 解析 roles: 通过 UserDetailsService 查 (client_credentials 模式无用户, roles 为空)
        Collection<GrantedAuthority> authorities = resolveAuthorities(principalName, scopes);

        log.debug("Opaque token introspect success, sub={}, scope={}", principalName, scopes);
        return new OpaquePrincipal(principalName, attributes, authorities);
    }

    /**
     * 解析权限: 优先从 UserDetailsService 查 roles; client_credentials 模式无用户时,
     * 把 scope 转成 ROLE_ 前缀的权限 (便于 @PreAuthorize 统一处理).
     */
    private Collection<GrantedAuthority> resolveAuthorities(String principalName, Set<String> scopes) {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        try {
            UserDetails user = portalUserDetailsService.loadUserByUsername(principalName);
            if (user != null) {
                user.getAuthorities().forEach(a -> authorities.add(new SimpleGrantedAuthority(a.getAuthority())));
                return authorities;
            }
        } catch (Exception e) {
            // client_credentials 模式 principalName=client_id, 查不到用户属正常
            log.debug("loadUserByUsername 失败 (可能是 client_credentials), principal={}", principalName);
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
