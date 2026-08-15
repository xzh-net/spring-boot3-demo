package net.xzh.authserver.security.authentication.grant;

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
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
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

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.ClientUserPolicyService;
import net.xzh.authserver.security.web.converter.PasswordGrantAuthenticationConverter;

/**
 * 密码授权模式认证提供者.
 * <p>
 * 职责：
 * 1. 校验客户端授权类型和请求 scope 是否合法。
 * 2. 验证资源所有者用户名和密码（通过 UserDetailsService + PasswordEncoder）。
 * 3. 生成 access_token（Opaque 短码）、可选的 refresh_token 和 OIDC id_token。
 * 4. 将授权记录持久化到 OAuth2AuthorizationService（Redis）。
 *
 * 架构定位：
 * 属于认证层（authentication/），处理纯逻辑验证与令牌生成，不涉及 HTTP 请求解析。
 * 接收 Converter 输出的 PasswordGrantAuthenticationToken，
 * 验证后输出 OAuth2AccessTokenAuthenticationToken。
 *
 * 令牌生成策略：
 * - access_token: Opaque（REFERENCE 格式），由 OAuth2AccessTokenGenerator 生成
 * - refresh_token: 当客户端配置了 refresh_token 授权类型时生成
 * - id_token: 当 authorizedScopes 包含 openid 时生成（OIDC 规范）
 */
@Slf4j
public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    /** RFC 6749 Section 5.2 — 令牌端点错误文档 URI */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    /** 客户端配置持久化仓库 */
    private final RegisteredClientRepository registeredClientRepository;

    /** 用户详情服务，用于加载用户凭据 */
    private final UserDetailsService userDetailsService;

    /** 密码编码器，用于验证用户密码 */
    private final PasswordEncoder passwordEncoder;

    /** OAuth2 授权持久化服务（Redis） */
    private final OAuth2AuthorizationService authorizationService;

    /** 令牌生成器，根据 TokenSettings.accessTokenFormat 选择生成策略 */
    private final OAuth2TokenGenerator<?> tokenGenerator;

    /** 令牌签发准入策略 (客户端 × 身份类型) */
    private final ClientUserPolicyService clientUserPolicyService;

    public PasswordGrantAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator,
            ClientUserPolicyService clientUserPolicyService) {
        this.registeredClientRepository = registeredClientRepository;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.clientUserPolicyService = clientUserPolicyService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken passwordAuth = (PasswordGrantAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal =
                (OAuth2ClientAuthenticationToken) passwordAuth.getClientPrincipal();
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // 1. 校验客户端是否支持 password 授权类型
        if (!registeredClient.getAuthorizationGrantTypes()
                .contains(PasswordGrantAuthenticationConverter.PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 2. 校验请求 scope 是否在客户端允许的范围内
        Set<String> requestedScopes = passwordAuth.getScopes();
        Set<String> allowedScopes = registeredClient.getScopes();
        if (!allowedScopes.containsAll(requestedScopes)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }

        // 3. 加载并验证资源所有者凭据
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(passwordAuth.getUsername());
        } catch (BadCredentialsException e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "用户名或密码错误", ERROR_URI));
        }

        if (!passwordEncoder.matches(passwordAuth.getPassword(), user.getPassword())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "用户名或密码错误", ERROR_URI));
        }

        // 令牌签发准入策略: 客户端 × 身份类型不匹配则拒绝签发 (不产生任何 token/授权记录)
        clientUserPolicyService.check(registeredClient, user.getUsername());

        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        Instant now = Instant.now();

        // 构建资源所有者认证对象（用于令牌生成时注入用户身份信息）
        Authentication resourceOwnerAuthentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        // 4. 构建授权记录（access_token 元数据中需保存 sub/scope/client_id 供 introspect 端点读取）
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(registeredClient.getId() + ":" + user.getUsername() + ":" + now.toEpochMilli())
                .principalName(user.getUsername())
                .authorizationGrantType(PasswordGrantAuthenticationConverter.PASSWORD)
                .authorizedScopes(requestedScopes.isEmpty() ? allowedScopes : requestedScopes)
                .attribute(Principal.class.getName(), resourceOwnerAuthentication)
                .attribute(Authentication.class.getName(), resourceOwnerAuthentication);

        // 5. 构建令牌生成上下文
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(authorizationBuilder.build())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .principal(resourceOwnerAuthentication)
                .authorizedScopes(requestedScopes.isEmpty() ? allowedScopes : requestedScopes)
                .authorizationGrantType(PasswordGrantAuthenticationConverter.PASSWORD);

        // ---- access_token ----
        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        OAuth2Token generatedRawToken = tokenGenerator.generate(accessTokenContext);
        OAuth2AccessToken rawTypedAccessToken = wrapAccessToken(generatedRawToken);

        // SAS Builder 的 token(...) 仅接受"纯 OAuth2AccessToken"（exact type match），
        // 对 OAuth2AccessTokenClaims 子类会静默丢弃，重建纯实例避免问题
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                rawTypedAccessToken.getTokenValue(),
                rawTypedAccessToken.getIssuedAt(),
                rawTypedAccessToken.getExpiresAt(),
                rawTypedAccessToken.getScopes());

        // access_token 元数据构建：提取 claims（JWT 有，Opaque 无），补齐 sub/scope/client_id
        Map<String, Object> atMeta = new HashMap<>();
        try {
            Method getClaims = generatedRawToken.getClass().getMethod("getClaims");
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) getClaims.invoke(generatedRawToken);
            if (claims != null && !claims.isEmpty()) {
                atMeta.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
            }
        } catch (NoSuchMethodException ignored) {
            // Opaque 短码无 claims，跳过
        } catch (Exception e) {
            log.debug("提取 access_token claims 失败 (非致命): {}", e.getMessage());
        }

        // 手动补齐 sub/scope/client_id，供 /oauth2/introspect 与 /userinfo 端点读取
        Set<String> authorizedScopesNow = requestedScopes.isEmpty() ? allowedScopes : requestedScopes;
        @SuppressWarnings("unchecked")
        Map<String, Object> existingClaims = (Map<String, Object>) atMeta.computeIfAbsent(
                OAuth2Authorization.Token.CLAIMS_METADATA_NAME, k -> new HashMap<>());
        existingClaims.putIfAbsent("sub", user.getUsername());
        existingClaims.putIfAbsent("scope", authorizedScopesNow);
        existingClaims.putIfAbsent("client_id", registeredClient.getClientId());

        // access_token 为 JWT (SELF_CONTAINED) 时额外保存 Jwt 实例
        if (generatedRawToken instanceof Jwt jwt) {
            authorizationBuilder.token(jwt, metadata ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()));
        }
        authorizationBuilder.token(accessToken, metadata -> metadata.putAll(atMeta));

        // ---- refresh_token ----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            OAuth2TokenContext refreshTokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();
            refreshToken = generateRefreshToken(refreshTokenContext);
            authorizationBuilder.refreshToken(refreshToken);
        }

        // ---- OIDC id_token ----
        // 当 authorizedScopes 包含 openid 时生成 id_token（OIDC Core 规范要求）
        Set<String> authorizedScopes = requestedScopes.isEmpty() ? allowedScopes : requestedScopes;
        if (authorizedScopes.contains("openid")) {
            Instant iat = now;
            Instant exp = accessToken != null
                    ? accessToken.getExpiresAt()
                    : now.plus(tokenSettings.getAccessTokenTimeToLive());

            // 模拟授权码 OIDC 上下文：生成一次性 OAuth2AuthorizationCode（附带 nonce），
            // 解决 refresh_token 刷新时 JwtGenerator 读取 idToken claims 的 NPE 问题
            byte[] nonceBytes = new byte[16];
            new SecureRandom().nextBytes(nonceBytes);
            String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            String codeValue = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("pwd-code-" + registeredClient.getId() + "-"
                            + user.getUsername() + "-" + now.toEpochMilli()).getBytes());
            OAuth2AuthorizationCode fakeCode = new OAuth2AuthorizationCode(codeValue, iat, exp);
            authorizationBuilder.token(fakeCode,
                    metadata -> metadata.put(OidcParameterNames.NONCE, nonce));

            OAuth2TokenContext idTokenContext = tokenContextBuilder
                    .tokenType(new OAuth2TokenType(OidcParameterNames.ID_TOKEN))
                    .build();
            OAuth2Token idTokenRaw = tokenGenerator.generate(idTokenContext);
            if (idTokenRaw instanceof Jwt idJwt) {
                OidcIdToken idToken = new OidcIdToken(
                        idJwt.getTokenValue(), idJwt.getIssuedAt(), idJwt.getExpiresAt(),
                        idJwt.getClaims());
                authorizationBuilder.token(idToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idJwt.getClaims()));
            } else if (generatedRawToken instanceof Jwt jwt) {
                // 兼容分支：access_token 为 JWT 时复用其 claims 构造 id_token
                OidcIdToken idToken = new OidcIdToken(
                        jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(),
                        jwt.getClaims());
                authorizationBuilder.token(idToken, metadata ->
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwt.getClaims()));
            }
        }

        // 6. 持久化授权记录
        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        // 7. 将 id_token 放入 additionalParams，SAS 会将其写入令牌响应 JSON
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

        log.info("Password grant success: client={}, user={}, id_token_incl={}",
                registeredClient.getClientId(),
                user.getUsername(),
                additionalParams.containsKey(OidcParameterNames.ID_TOKEN));
        return result;
    }

    /**
     * 将 TokenGenerator 生成的令牌转换为 OAuth2AccessToken。
     * 处理三种情况：null → 抛异常，OAuth2AccessToken → 直接返回，Jwt → 转换为 OAuth2AccessToken。
     */
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

    /**
     * 生成 refresh_token。如果生成结果不是 OAuth2RefreshToken 类型则返回 null。
     */
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

    /**
     * 判断本 Provider 是否支持给定的 Authentication 类型。
     * 支持所有 PasswordGrantAuthenticationToken 实例（其子类也可匹配）。
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}