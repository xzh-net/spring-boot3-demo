package net.xzh.authserver.security.token;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.CollectionUtils;

/**
 * 增强版 Token Introspection 认证提供者.
 *
 * <p>目的: 解决 Opaque access_token 在「授权码模式 (authorization_code)」下无法内省出用户身份的问题。
 * SAS 默认的 {@code OAuth2TokenIntrospectionAuthenticationProvider} 读取的是 access_token 元数据中的
 * claims ({@code oauth2.token.claims}), 而该元数据只在 token 是 JWT (ClaimAccessor) 时才被写入。
 * 本项目 access_token 统一为 Opaque 引用格式, 授权码流程不会写入 claims 元数据,
 * 导致 {@code sub} (用户名) 缺失。</p>
 *
 * <p>本提供者替换默认提供者, 在原有逻辑基础上强制补充: {@code sub} (授权主体验证名)、
 * {@code scope} (授权范围)、{@code client_id} (签发该 token 的客户端标识),
 * 从而资源服务器按 {@code sub} 查询 RBAC 权限时对所有授权流程都可用。</p>
 *
 * <p>注册方式: {@code tokenIntrospectionEndpoint(tie -> tie.authenticationProviders(
 * providers -> { providers.removeIf(p -> p instanceof OAuth2TokenIntrospectionAuthenticationProvider);
 * providers.add(new EnrichedOAuth2TokenIntrospectionAuthenticationProvider(...)); }))}</p>
 */
public final class EnrichedOAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

	private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

	private static final TypeDescriptor LIST_STRING_TYPE_DESCRIPTOR = TypeDescriptor.collection(List.class,
			TypeDescriptor.valueOf(String.class));

	private final RegisteredClientRepository registeredClientRepository;

	private final OAuth2AuthorizationService authorizationService;

	public EnrichedOAuth2TokenIntrospectionAuthenticationProvider(
			RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		this.registeredClientRepository = registeredClientRepository;
		this.authorizationService = authorizationService;
	}

	/** access_token 的预期受众 (与 AuthorizationServerConfig.CONTACTS_API_AUD 保持一致) */
	private static final String CONTACTS_API_AUD = "contacts-api";

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication =
				(OAuth2TokenIntrospectionAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
				tokenIntrospectionAuthentication);

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(tokenIntrospectionAuthentication.getToken(), null);
		if (authorization == null) {
			// Token not found → 返回请求本身, 由授权过滤器输出 active=false 响应
			return tokenIntrospectionAuthentication;
		}

		OAuth2Authorization.Token<OAuth2Token> authorizedToken = authorization
			.getToken(tokenIntrospectionAuthentication.getToken());
		if (authorizedToken == null || !authorizedToken.isActive()) {
			return new OAuth2TokenIntrospectionAuthenticationToken(tokenIntrospectionAuthentication.getToken(),
					clientPrincipal, OAuth2TokenIntrospection.builder().build());
		}

		RegisteredClient authorizedClient = this.registeredClientRepository
			.findById(authorization.getRegisteredClientId());
		OAuth2TokenIntrospection tokenClaims = withActiveTokenClaims(authorization, authorizedToken, authorizedClient);

		return new OAuth2TokenIntrospectionAuthenticationToken(
				authorizedToken.getToken().getTokenValue(), clientPrincipal, tokenClaims);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * 组装内省响应 claims: 复用 token 元数据中的 claims (如有), 并强制补齐 sub/scope/client_id.
	 */
	private static OAuth2TokenIntrospection withActiveTokenClaims(
			OAuth2Authorization authorization,
			OAuth2Authorization.Token<OAuth2Token> authorizedToken,
			RegisteredClient authorizedClient) {

		OAuth2TokenIntrospection.Builder tokenClaims;
		Map<String, Object> existingClaims = CollectionUtils.isEmpty(authorizedToken.getClaims()) ? null
				: convertClaimsIfNecessary(authorizedToken.getClaims());
		if (existingClaims != null) {
			tokenClaims = OAuth2TokenIntrospection.withClaims(existingClaims).active(true);
		} else {
			tokenClaims = OAuth2TokenIntrospection.builder(true);
		}

		// 【增强】无条件写入 sub = 授权主体 (授权码/password/设备码为用户名,
		//          client_credentials 为 client_id). 这是资源服务器定位用户的依据.
		tokenClaims.subject(authorization.getPrincipalName());

		// 【增强】无条件写入 grant_type = 该 token 的授权类型 (authorization_code / password /
		//          client_credentials ...). 资源服务器据此区分「用户令牌」与「服务令牌」(M2M).
		if (authorization.getAuthorizationGrantType() != null) {
			tokenClaims.claim("grant_type", authorization.getAuthorizationGrantType().getValue());
		}

		// 【增强】无条件写入 client_id = 签发该 token 的客户端对外标识
		String clientId = (authorizedClient != null) ? authorizedClient.getClientId()
				: authorization.getRegisteredClientId();
		tokenClaims.clientId(clientId);

		// 【增强】无条件写入 scope (若 token 元数据 claims 中缺失)
		if ((existingClaims == null || !existingClaims.containsKey(OAuth2TokenIntrospectionClaimNames.SCOPE))
				&& !CollectionUtils.isEmpty(authorization.getAuthorizedScopes())) {
			tokenClaims.scopes(list -> list.addAll(authorization.getAuthorizedScopes()));
		}

		// 【增强】无条件写入 aud (Opaque token 无 claims 元数据, 补齐约定的资源受众)
		if (existingClaims == null || !existingClaims.containsKey(OAuth2TokenIntrospectionClaimNames.AUD)) {
			tokenClaims.audience(CONTACTS_API_AUD);
		}

		OAuth2Token token = authorizedToken.getToken();
		if (token.getIssuedAt() != null) {
			tokenClaims.issuedAt(token.getIssuedAt());
		}
		if (token.getExpiresAt() != null) {
			tokenClaims.expiresAt(token.getExpiresAt());
		}

		if (OAuth2AccessToken.class.isAssignableFrom(token.getClass())) {
			OAuth2AccessToken accessToken = (OAuth2AccessToken) token;
			tokenClaims.tokenType(accessToken.getTokenType().getValue());
		}

		return tokenClaims.build();
	}

	/**
	 * 将 claims 中的 iss/scope/aud 统一成内省响应要求的类型 (URL / List).
	 */
	private static Map<String, Object> convertClaimsIfNecessary(Map<String, Object> claims) {
		Map<String, Object> convertedClaims = new HashMap<>(claims);

		Object value = claims.get(OAuth2TokenIntrospectionClaimNames.ISS);
		if (value != null && !(value instanceof URL)) {
			URL convertedValue = ClaimConversionService.getSharedInstance().convert(value, URL.class);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.ISS, convertedValue);
			}
		}

		value = claims.get(OAuth2TokenIntrospectionClaimNames.SCOPE);
		if (value != null && !(value instanceof List)) {
			Object convertedValue = ClaimConversionService.getSharedInstance()
				.convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE, convertedValue);
			}
		}

		value = claims.get(OAuth2TokenIntrospectionClaimNames.AUD);
		if (value != null && !(value instanceof List)) {
			Object convertedValue = ClaimConversionService.getSharedInstance()
				.convert(value, OBJECT_TYPE_DESCRIPTOR, LIST_STRING_TYPE_DESCRIPTOR);
			if (convertedValue != null) {
				convertedClaims.put(OAuth2TokenIntrospectionClaimNames.AUD, convertedValue);
			}
		}

		return convertedClaims;
	}

	/**
	 * 提取已认证的客户端身份; 未认证则抛 invalid_client 异常.
	 * (OAuth2AuthenticationProviderUtils 为包内私有类, 此处等价复刻其逻辑)
	 */
	private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
			Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}
}