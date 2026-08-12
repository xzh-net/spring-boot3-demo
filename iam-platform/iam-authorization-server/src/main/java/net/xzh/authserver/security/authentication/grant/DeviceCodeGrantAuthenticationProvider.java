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

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 设备码授权模式认证提供者.
 * <p>
 * 职责：
 * <ol>
 *   <li>验证 device_code 有效性（存在、未过期、未失效、客户端匹配）。</li>
 *   <li>检查 userCode 状态：未失效 → authorization_pending（轮询继续），已失效且未拒绝 → 签发 token。</li>
 *   <li>重新加载真实用户 authorities（不依赖 Redis 反序列化的 stub Principal）。</li>
 *   <li>生成 access_token（Opaque 短码）、可选的 refresh_token 和 OIDC id_token。</li>
 *   <li>将授权记录持久化到 OAuth2AuthorizationService（Redis）。</li>
 * </ol>
 *
 * 架构定位：
 * 属于认证层（authentication/），处理纯逻辑验证与令牌生成，不涉及 HTTP 请求解析。
 * 替换 SAS 默认的 OAuth2DeviceCodeAuthenticationProvider。
 *
 * 关键约束：
 * <ul>
 *   <li>id_token 生成由 openid scope + 客户端配置 + 用户同意三方驱动，无硬编码。</li>
 *   <li>模拟授权码 OIDC 上下文（一次性 OAuth2AuthorizationCode + nonce），解决 refresh_token
 *       刷新时 JwtGenerator 读取 idToken claims 的 NPE 问题。</li>
 *   <li>device_code 失效与过期场景与 SAS 默认 Provider 行为完全一致。</li>
 * </ul>
 *
 * @see PasswordGrantAuthenticationProvider
 */
@Slf4j
public final class DeviceCodeGrantAuthenticationProvider implements AuthenticationProvider {

    /** RFC 8628 Section 3.5 — 设备码授权错误文档 URI */
    private static final String DEVICE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5";

    /** RFC 6749 Section 5.2 — 通用令牌端点错误文档 URI */
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    /** device_code 令牌类型常量，用于按 token 值查找授权记录 */
    private static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType("device_code");

    /** 客户端配置持久化仓库 */
    private final RegisteredClientRepository registeredClientRepository;

    /** OAuth2 授权持久化服务（Redis） */
    private final OAuth2AuthorizationService authorizationService;

    /** 用户详情服务，用于加载真实用户 authorities */
    private final UserDetailsService userDetailsService;

    /** 令牌生成器，根据 TokenSettings.accessTokenFormat 选择生成策略 */
    private final OAuth2TokenGenerator<?> tokenGenerator;

    public DeviceCodeGrantAuthenticationProvider(
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            UserDetailsService userDetailsService,
            OAuth2TokenGenerator<?> tokenGenerator) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
        this.userDetailsService = userDetailsService;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2DeviceCodeAuthenticationToken deviceCodeAuth = (OAuth2DeviceCodeAuthenticationToken) authentication;

        // ---- 1. 客户端主体验证 ----
        // SAS 7.1.0 的 OAuth2AuthorizationGrantAuthenticationToken.getClientPrincipal() 为包级私有,
        // OAuth2AuthenticationProviderUtils 也在 authentication 包内不可外部调用.
        // 客户端主体通过公共 getPrincipal() 获取 (基类 getPrincipal() 返回 clientPrincipal 字段).
        Object principalObj = authentication.getPrincipal();
        if (!(principalObj instanceof OAuth2ClientAuthenticationToken clientPrincipal)
                || !clientPrincipal.isAuthenticated()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
        }

        // ---- 2. 校验客户端授权类型包含 device_code ----
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.DEVICE_CODE)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // ---- 3. 查找 device_code 对应的授权记录 ----
        OAuth2Authorization authorization = authorizationService.findByToken(
                deviceCodeAuth.getDeviceCode(), DEVICE_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // ---- 4. 验证 device_code 有效性 ----
        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCodeToken = authorization.getToken(OAuth2DeviceCode.class);
        if (deviceCodeToken == null || deviceCodeToken.getToken() == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // 客户端不匹配 → 使 deviceCode 失效 + 抛出 invalid_grant
        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
            invalidateDeviceCode(authorization, deviceCodeToken);
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // device_code 已失效 → invalid_grant
        if (deviceCodeToken.isInvalidated()) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // device_code 已过期 → 使其失效 + 抛出 expired_token
        if (deviceCodeToken.isExpired()) {
            invalidateDeviceCode(authorization, deviceCodeToken);
            throw new OAuth2AuthenticationException(new OAuth2Error("expired_token", null, DEVICE_ERROR_URI));
        }

        // ---- 5. 检查 userCode 状态 ----
        OAuth2Authorization.Token<OAuth2UserCode> userCodeToken = authorization.getToken(OAuth2UserCode.class);
        if (userCodeToken == null || userCodeToken.getToken() == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        // userCode 未失效 → 用户尚未完成授权 → 返回 authorization_pending（设备端继续轮询）
        if (!userCodeToken.isInvalidated()) {
            throw new OAuth2AuthenticationException(new OAuth2Error("authorization_pending", null, DEVICE_ERROR_URI));
        }

        // deviceCode 已失效（用户在授权页点了"拒绝"）→ 返回 access_denied
        if (deviceCodeToken.isInvalidated()) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, null, DEVICE_ERROR_URI));
        }

        // ---- 6. 校验通过，用户已同意授权，开始签发 token ----

        // 重新加载真实用户：获取真实 authorities（id_token roles claim）并校验用户未停用
        // 不依赖 Redis 反序列化的 stub Principal（其 authorities 仅 ROLE_USER）
        String principalName = authorization.getPrincipalName();
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(principalName);
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, "用户不存在或已停用", DEVICE_ERROR_URI));
        }

        // 构建资源所有者认证对象（用于令牌生成时注入用户身份信息）
        Authentication resourceOwnerAuthentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        // 基于现有授权构建 Builder：保留 device_code/user_code（Redis 索引不丢失），不新建授权记录
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
                .principalName(user.getUsername())
                .attribute(Principal.class.getName(), resourceOwnerAuthentication)
                .attribute(Authentication.class.getName(), resourceOwnerAuthentication);

        // authorizedScopes = 客户端配置 ∩ 请求参数 ∩ 用户同意
        Set<String> authorizedScopes = authorization.getAuthorizedScopes();
        if (authorizedScopes == null || authorizedScopes.isEmpty()) {
            authorizedScopes = registeredClient.getScopes();
        }

        TokenSettings tokenSettings = registeredClient.getTokenSettings();
        Instant now = Instant.now();

        // 构建令牌生成上下文
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .authorization(authorizationBuilder.build())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .principal(resourceOwnerAuthentication)
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE);

        // ---- access_token（Opaque 短码） ----
        OAuth2TokenContext accessTokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        OAuth2Token generatedRawToken = tokenGenerator.generate(accessTokenContext);
        OAuth2AccessToken rawTypedAccessToken = wrapAccessToken(generatedRawToken);

        // SAS Builder 的 token(...) 仅接受"纯 OAuth2AccessToken"，对 claims 子类会静默丢弃
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
        Set<String> finalAuthorizedScopes = authorizedScopes;
        @SuppressWarnings("unchecked")
        Map<String, Object> existingClaims = (Map<String, Object>) atMeta.computeIfAbsent(
                OAuth2Authorization.Token.CLAIMS_METADATA_NAME, k -> new HashMap<>());
        existingClaims.putIfAbsent("sub", user.getUsername());
        existingClaims.putIfAbsent("scope", finalAuthorizedScopes);
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
            if (refreshToken != null) {
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        // ---- OIDC id_token（当 authorizedScopes 含 openid） ----
        // 是否生成 id_token 完全取决于 authorizedScopes 是否含 openid，即：
        //   客户端注册了 openid scope + 客户端请求带 openid + 用户同意 openid
        // 三者均满足才生成，与 OIDC Core 规范一致，无任何硬编码
        if (authorizedScopes.contains("openid")) {
            Instant iat = now;
            Instant exp = accessToken != null ? accessToken.getExpiresAt()
                    : now.plus(tokenSettings.getAccessTokenTimeToLive());

            // 模拟授权码 OIDC 上下文：生成一次性 OAuth2AuthorizationCode（附带 nonce）
            // 解决 refresh_token 时 JwtGenerator 读取 idToken 复制 claims 的 NPE 问题
            byte[] nonceBytes = new byte[16];
            new SecureRandom().nextBytes(nonceBytes);
            String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            String codeValue = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("device-code-" + registeredClient.getId() + "-"
                            + user.getUsername() + "-" + now.toEpochMilli()).getBytes());
            OAuth2AuthorizationCode fakeCode = new OAuth2AuthorizationCode(codeValue, iat, exp);
            authorizationBuilder.token(fakeCode, metadata -> metadata.put(OidcParameterNames.NONCE, nonce));

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

        // ---- 7. 持久化授权记录 ----
        OAuth2Authorization updatedAuthorization = authorizationBuilder.build();
        authorizationService.save(updatedAuthorization);

        // 将 id_token 放入 additionalParams，SAS 会将其写入令牌响应 JSON
        Map<String, Object> additionalParams = new HashMap<>();
        OAuth2Authorization.Token<OidcIdToken> idTokenWrapper = updatedAuthorization.getToken(OidcIdToken.class);
        if (idTokenWrapper != null && idTokenWrapper.getToken() != null) {
            additionalParams.put(OidcParameterNames.ID_TOKEN, idTokenWrapper.getToken().getTokenValue());
        }

        OAuth2AccessTokenAuthenticationToken result = new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParams);

        log.info("Device code grant success: client={}, user={}, id_token_incl={}",
                registeredClient.getClientId(), user.getUsername(),
                additionalParams.containsKey(OidcParameterNames.ID_TOKEN));
        return result;
    }

    /**
     * 标记 deviceCode 失效并保存到 Redis。
     * 用于客户端不匹配或 device_code 过期场景，与 SAS 默认 Provider 行为一致。
     */
    private void invalidateDeviceCode(OAuth2Authorization authorization,
                                      OAuth2Authorization.Token<OAuth2DeviceCode> deviceCodeToken) {
        try {
            OAuth2Authorization invalidated = OAuth2Authorization.from(authorization)
                    .invalidate(deviceCodeToken.getToken())
                    .build();
            authorizationService.save(invalidated);
            log.warn("Invalidated device code used by registered client '{}'", authorization.getRegisteredClientId());
        } catch (Exception e) {
            log.debug("invalidateDeviceCode 失败 (非致命): {}", e.getMessage());
        }
    }

    /**
     * 将 TokenGenerator 生成的令牌转换为 OAuth2AccessToken。
     * 处理三种情况：null → 抛异常，OAuth2AccessToken → 直接返回，Jwt → 转换为 OAuth2AccessToken。
     */
    private OAuth2AccessToken wrapAccessToken(OAuth2Token generated) {
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("token_generation_error",
                    "无法生成 access token", DEFAULT_ERROR_URI));
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
                "生成的 token 类型不匹配: " + generated.getClass().getSimpleName(), DEFAULT_ERROR_URI));
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
     * 支持所有 OAuth2DeviceCodeAuthenticationToken 实例（其子类也可匹配）。
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2DeviceCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}