package net.xzh.authserver.security.authentication.grant.password;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.lang.reflect.Method;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final RegisteredClientRepository registeredClientRepository;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<?> tokenGenerator;

    public PasswordGrantAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) {
        this.registeredClientRepository = registeredClientRepository;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken passwordAuth = (PasswordGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = (OAuth2ClientAuthenticationToken) passwordAuth.getClientPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (!registeredClient.getAuthorizationGrantTypes().contains(PasswordGrantAuthenticationConverter.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        Set<String> requestedScopes = passwordAuth.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        if (!allowedScopes.containsAll(requestedScopes)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }

        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(passwordAuth.getUsername());
        } catch (BadCredentialsException e) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "用户名或密码错误", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (!passwordEncoder.matches(passwordAuth.getPassword(), user.getPassword())) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "用户名或密码错误", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        Instant now = Instant.now();

        Authentication resourceOwnerAuthentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId() + ":" + user.getUsername() + ":" + now.toEpochMilli())
                .principalName(user.getUsername())
                .authorizationGrantType(PasswordGrantAuthenticationConverter.PASSWORD)
                .authorizedScopes(requestedScopes.isEmpty() ? allowedScopes : requestedScopes)
                .attribute(Principal.class.getName(), resourceOwnerAuthentication)
                .attribute(Authentication.class.getName(), resourceOwnerAuthentication);

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(authorizationBuilder.build())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .principal(resourceOwnerAuthentication)
                .authorizedScopes(requestedScopes.isEmpty() ? allowedScopes : requestedScopes)
                .authorizationGrantType(PasswordGrantAuthenticationConverter.PASSWORD);

        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        // tokenGenerator 根据 TokenSettings.accessTokenFormat 选择生成器:
        //   REFERENCE     → OAuth2AccessTokenGenerator (Opaque 短码, 当前所有客户端采用)
        //   SELF_CONTAINED → JwtGenerator (JWT, 预留兼容)
        OAuth2Token generatedRawToken = tokenGenerator.generate(accessTokenContext);
        OAuth2AccessToken rawTypedAccessToken = wrapAccessToken(generatedRawToken);
        log.debug("access_token 生成: type={}, valueLen={}",
                generatedRawToken != null ? generatedRawToken.getClass().getSimpleName() : "null",
                rawTypedAccessToken.getTokenValue().length());

        // SAS Builder 的 token(...) 仅接受"纯 OAuth2AccessToken" (exact type match),
        // 对 OAuth2AccessTokenClaims 子类会静默丢弃, 因此重建一个不带 claims 子类的实例.
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                rawTypedAccessToken.getTokenValue(),
                rawTypedAccessToken.getIssuedAt(),
                rawTypedAccessToken.getExpiresAt(),
                rawTypedAccessToken.getScopes());

        Map<String, Object> atMeta = new HashMap<>();
        // access_token 为 SELF_CONTAINED (JWT) 时, generatedRawToken 是带 claims 的子类,
        // 反射提取 claims 存入 metadata; REFERENCE (Opaque) 时无 getClaims 方法, 直接跳过.
        try {
            Method getClaims = generatedRawToken.getClass().getMethod("getClaims");
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) getClaims.invoke(generatedRawToken);
            if (claims != null && !claims.isEmpty()) {
                atMeta.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
            }
        } catch (NoSuchMethodException ignored) {
            // Opaque 短码无 claims, 跳过
        } catch (Exception e) {
            log.debug("提取 access_token claims 失败 (非致命): {}", e.getMessage());
        }
        // 手动补齐 sub/scope/client_id, 供 /oauth2/introspect 与 /userinfo 端点读取.
        // Opaque 模式下 access_token 本身无 claims, 这些信息只通过 metadata 暴露给本服务端点,
        // 资源服务器 (/api/**) 走 RedisOpaqueTokenIntrospector, 不读此 metadata.
        Set<String> authorizedScopesNow = requestedScopes.isEmpty() ? allowedScopes : requestedScopes;
        @SuppressWarnings("unchecked")
        Map<String, Object> existingClaims = (Map<String, Object>) atMeta.computeIfAbsent(
                OAuth2Authorization.Token.CLAIMS_METADATA_NAME, k -> new HashMap<>());
        existingClaims.putIfAbsent("sub", user.getUsername());
        existingClaims.putIfAbsent("scope", authorizedScopesNow);
        existingClaims.putIfAbsent("client_id", registeredClient.getClientId());
        // access_token 为 JWT (SELF_CONTAINED) 时额外保存 Jwt 实例, refresh 流程中 JwtGenerator 需要查找
        if (generatedRawToken instanceof Jwt jwt) {
            authorizationBuilder.token(jwt, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()));
        }
        // 用纯 OAuth2AccessToken + metadata 存 (SAS Builder 才能正确识别到 access_token wrapper)
        authorizationBuilder.token(accessToken, metadata -> metadata.putAll(atMeta));

        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();
            refreshToken = generateRefreshToken(refreshTokenContext);
            authorizationBuilder.refreshToken(refreshToken);
        }
        // OIDC id_token 生成: password grant 无浏览器跳转, 需手动构造 OIDC 上下文.
        // 1) 保存一次性 OAuth2AuthorizationCode (附带 nonce), 模拟授权码流程的 OIDC 上下文,
        //    解决 refresh_token 时 JwtGenerator 读取 idToken 复制 claims 的 NPE 问题.
        // 2) 单独生成 id_token (JWT), 与 access_token 格式无关 (Opaque 也能生成 id_token).
        Set<String> authorizedScopes = requestedScopes.isEmpty() ? allowedScopes : requestedScopes;
        if (authorizedScopes.contains("openid")) {
            Instant iat = now;
            Instant exp = accessToken != null ? accessToken.getExpiresAt() : now.plus(tokenSettings.getAccessTokenTimeToLive());
            byte[] nonceBytes = new byte[16];
            new SecureRandom().nextBytes(nonceBytes);
            String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            String codeValue = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("pwd-code-" + registeredClient.getId() + "-" + user.getUsername() + "-" + now.toEpochMilli()).getBytes());
            OAuth2AuthorizationCode fakeCode = new OAuth2AuthorizationCode(codeValue, iat, exp);
            authorizationBuilder.token(fakeCode, metadata -> metadata.put(OidcParameterNames.NONCE, nonce));
            OAuth2TokenContext idTokenContext = tokenContextBuilder
                    .tokenType(new OAuth2TokenType(OidcParameterNames.ID_TOKEN))
                    .build();
            OAuth2Token idTokenRaw = tokenGenerator.generate(idTokenContext);
            if (idTokenRaw instanceof Jwt idJwt) {
                OidcIdToken idToken = new OidcIdToken(idJwt.getTokenValue(), idJwt.getIssuedAt(), idJwt.getExpiresAt(), idJwt.getClaims());
                authorizationBuilder.token(idToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idJwt.getClaims()));
            } else if (generatedRawToken instanceof Jwt jwt) {
                // 兼容分支: access_token 为 JWT 时复用其 claims 构造 id_token (理论上不会走到, 因当前 access_token 是 Opaque)
                OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
                authorizationBuilder.token(idToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()));
            }
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        // 将 id_token 放入 additionalParams, SAS 的 token 响应处理器会将其写入最终 JSON
        Map<String, Object> additionalParams = new HashMap<>();
        OAuth2Authorization.Token<OidcIdToken> idTokenWrapper = authorization.getToken(OidcIdToken.class);
        if (idTokenWrapper != null && idTokenWrapper.getToken() != null) {
            additionalParams.put(OidcParameterNames.ID_TOKEN, idTokenWrapper.getToken().getTokenValue());
        }

        OAuth2AccessTokenAuthenticationToken result = new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParams);

        log.info("Password grant success: client={}, user={}, id_token_incl={}", registeredClient.getClientId(),
                user.getUsername(), additionalParams.containsKey(OidcParameterNames.ID_TOKEN));
        return result;
    }

    private OAuth2AccessToken wrapAccessToken(OAuth2Token generated) {
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("token_generation_error",
                    "无法生成 access token", ERROR_URI));
        }

        if (generated instanceof OAuth2AccessToken accessToken) {
            return accessToken;
        }

        if (generated instanceof Jwt jwt) {
            Set<String> scopes = new HashSet<>();
            List<String> scopeList = jwt.getClaimAsStringList("scope");
            if (scopeList != null) {
                scopes.addAll(scopeList);
            }
            return new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    jwt.getTokenValue(),
                    jwt.getIssuedAt(),
                    jwt.getExpiresAt(),
                    scopes);
        }

        throw new OAuth2AuthenticationException(new OAuth2Error("token_generation_error",
                "生成的 token 类型不匹配: " + generated.getClass().getSimpleName(), ERROR_URI));
    }

    private OAuth2RefreshToken generateRefreshToken(OAuth2TokenContext context) {
        OAuth2Token generated = tokenGenerator.generate(context);
        if (generated == null) {
            return null;
        }
        if (!(generated instanceof OAuth2RefreshToken refreshToken)) {
            return null;
        }
        return refreshToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
