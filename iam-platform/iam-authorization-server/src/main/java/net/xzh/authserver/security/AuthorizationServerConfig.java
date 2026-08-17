package net.xzh.authserver.security;

import java.net.URI;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.AuthServerProperties;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;
import net.xzh.authserver.security.ClientUserPolicyService;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.authentication.client.DeviceClientAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.DeviceCodeGrantAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.PasswordGrantAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.PolicyAwareAuthorizationCodeAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.PolicyAwareRefreshTokenAuthenticationProvider;
import net.xzh.authserver.security.session.RedisSessionRegistry;
import net.xzh.authserver.security.token.EnrichedOAuth2TokenIntrospectionAuthenticationProvider;
import net.xzh.authserver.security.token.RedisOpaqueTokenIntrospector;
import net.xzh.authserver.security.web.ActiveClientTrackingFilter;
import net.xzh.authserver.security.web.AuthorizePolicyFilter;
import net.xzh.authserver.security.web.CompositeSecurityContextRepository;
import net.xzh.authserver.security.web.SessionExpirationFilter;
import net.xzh.authserver.security.web.converter.DeviceClientAuthenticationConverter;
import net.xzh.authserver.security.web.converter.PasswordGrantAuthenticationConverter;

/**
 * Spring Authorization Server 核心配置类.
 * <p>
 * 职责：
 * <ol>
 * <li>定义 3 条 SecurityFilterChain，按优先级处理不同的请求路径。</li>
 * <li>配置 OAuth2 授权服务器端点（授权码、设备码、令牌、内省、撤销、JWKS、OIDC）。</li>
 * <li>配置 TokenGenerator 链路：OAuth2AccessTokenGenerator → JwtGenerator，access_token 固定为 Opaque 格式，id_token 为 JWT。</li>
 * <li>注册自定义认证 Provider（密码授权、设备码授权、设备码客户端认证、增强内省）。</li>
 * <li>管理安全上下文隔离：OAuth2 授权登录 / 设备验证使用独立的 SecurityContext Key。</li>
 * </ol>
 *
 * 3 条 FilterChain 概览：
 * <ul>
 * <li><b>Order(1)</b> — OAuth2 认证链：OAuth2 端点 + 登录页（授权、令牌、内省、撤销、设备码、JWKS、OIDC、/login、/logout、/userinfo）</li>
 * <li><b>Order(2)</b> — 管理 REST API 链：/api/admin/**（Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证 + 白名单客户端）</li>
 * <li><b>Order(3)</b> — 设备验证链：/activate、/device-login（独立 SecurityContext Key）</li>
 * </ul>
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	/** 管理服务凭证类别标识 (用户令牌持有者具备管理端业务角色时签发), 管理 REST API 链以此裁决 */
	private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

	/** 管理端业务角色编码 (逻辑引用资源中心 sys_role.role_code) */
	private static final String ADMIN_ROLE_CODE = "ADMIN";

	/** OAuth2 授权码登录态的 SecurityContext 在会话中的属性键 */
	public static final String PORTAL_CONTEXT_KEY = "PORTAL_SECURITY_CONTEXT";

	/** 设备验证流程的 SecurityContext 在会话中的属性键 */
	static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

	/** OAuth2 令牌的预期受众（用于 introspection 的 aud claim） */
	static final String CONTACTS_API_AUD = "contacts-api";

	private final AuthServerProperties authServerProperties;

	public AuthorizationServerConfig(AuthServerProperties authServerProperties) {
		this.authServerProperties = authServerProperties;
	}

	// ------------------------------------------------------------------
	// Bean 组件
	// ------------------------------------------------------------------

	/**
	 * 基于 Redis 的 SessionRegistry：会话跟踪索引持久化到 Redis，
	 * 服务器重启后在线用户列表不丢失。
	 */
	@Bean
	public RedisSessionRegistry sessionRegistry(StringRedisTemplate redisTemplate) {
		log.info("使用 RedisSessionRegistry, 会话跟踪信息持久化到 Redis");
		return new RedisSessionRegistry(redisTemplate);
	}

	/** 将 HttpSession 事件转发给 SessionRegistry，保证会话生命周期正确跟踪 */
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	@Bean
	public RSAKey rsaKey() {
		try {
			return new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
		} catch (Exception e) {
			throw new RuntimeException("生成 RSA 密钥失败", e);
		}
	}

	@Bean
	public ECKey ecKey() {
		try {
			return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
		} catch (Exception e) {
			throw new RuntimeException("生成 EC 密钥失败", e);
		}
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey, ECKey ecKey) {
		return (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(List.of(rsaKey, ecKey)));
	}

	/** 仅用于 id_token 校验，access_token 走 Opaque introspect */
	@Bean
	@Primary
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		NimbusJwtDecoder decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("http://localhost:9000"));
		return decoder;
	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

	/**
	 * TokenGenerator 链路: Opaque access_token → JWT id_token → refresh_token.
	 * <p>
	 * OAuth2AccessTokenGenerator 排在 JwtGenerator 前面是为了绕过 SAS 1.4.1 的 bug:
	 * JwtGenerator.supports() 对 access_token 不检查 TokenSettings.format, 直接返回 true,
	 * 会抢占生成 JWT access_token. OAuth2AccessTokenGenerator 不支持 id_token, 自动 fallback
	 * 到 JwtGenerator 处理 id_token.
	 */
	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JwtEncoder jwtEncoder,
			OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(accessTokenGenerator, jwtGenerator,
				new OAuth2RefreshTokenGenerator());
	}

	/**
	 * 授权登录用户的 DaoAuthenticationProvider，供 OAuth2 授权登录与设备验证链路共用。
	 */
	@Bean("portalDaoProvider")
	public DaoAuthenticationProvider portalDaoProvider(
			@Qualifier("portalUserDetailsService") UserDetailsService portalUserDetailsService,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(portalUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

	/**
	 * 自定义 Token Customizer: 为 access_token 设置 aud claim, 为 id_token 设置 roles +
	 * preferred_username. 处理两种 principal 类型: UserDetails (授权码) 和
	 * UsernamePasswordAuthenticationToken (密码/刷新).
	 * <p>
	 * V6.2: principal name 为业务用户编码 user_code (令牌 sub), roles 来自资源中心 RBAC;
	 * preferred_username 保持真实登录用户名 (按 user_code 反查 iam_identity.sys_user)。
	 */
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(SysUserMapper sysUserMapper) {
		return context -> {
			String tokenType = context.getTokenType().getValue();
			if ("access_token".equals(tokenType)) {
				context.getClaims().claim("aud", Set.of(CONTACTS_API_AUD));
			}
			if (context.getAuthorization() == null || context.getPrincipal() == null)
				return;
			Object principal = context.getPrincipal();
			String userCode = null;
			Collection<? extends GrantedAuthority> authorities = List.of();
			if (principal instanceof UserDetails user) {
				userCode = user.getUsername();
				authorities = user.getAuthorities();
			} else if (principal instanceof UsernamePasswordAuthenticationToken upat) {
				Object inner = upat.getPrincipal();
				if (inner instanceof UserDetails innerUser) {
					userCode = innerUser.getUsername();
					authorities = innerUser.getAuthorities();
				} else if (inner != null) {
					userCode = inner.toString();
					authorities = upat.getAuthorities();
				}
			}
			final String codeFinal = userCode;
			final var authFinal = authorities;
			if (codeFinal != null) {
				context.getClaims().claims(claims -> {
					claims.put("roles", authFinal.stream().map(a -> a.getAuthority()).toList());
					if ("id_token".equals(tokenType)) {
						claims.put("preferred_username", resolveUsername(sysUserMapper, codeFinal));
					}
				});
			}
		};
	}

	/**
	 * 按业务用户编码反查真实登录用户名 (id_token preferred_username 用, 查不到时降级返回 user_code)。
	 */
	private static String resolveUsername(SysUserMapper sysUserMapper, String userCode) {
		try {
			SysUser u = sysUserMapper.selectOne(new QueryWrapper<SysUser>().eq("user_code", userCode));
			if (u != null && u.getUsername() != null && !u.getUsername().isBlank()) {
				return u.getUsername();
			}
		} catch (Exception e) {
			// ignore, fallback to user_code
		}
		return userCode;
	}

	/** 全局 TokenSettings: 固定 Opaque 格式, 不允许客户端覆盖; refresh TTL 默认 12h (设计 §8) */
	@Bean
	public TokenSettings tokenSettings() {
		return TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
				.accessTokenTimeToLive(Duration.ofHours(2)).authorizationCodeTimeToLive(Duration.ofMinutes(5))
				.refreshTokenTimeToLive(Duration.ofHours(12)).reuseRefreshTokens(true).build();
	}

	// ------------------------------------------------------------------
	// 链 1: OAuth2 认证链（最高优先级）
	// ------------------------------------------------------------------

	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			RegisteredClientRepository registeredClientRepository, RedisOAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService, OAuth2TokenGenerator<?> tokenGenerator,
			@Qualifier("portalUserDetailsService") UserDetailsService portalUserDetailsService,
			PasswordEncoder passwordEncoder,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider,
			SessionRegistry sessionRegistry, ClientUserPolicyService clientUserPolicyService) throws Exception {

		// 1. 准备自定义的认证组件
		// 创建用于设备授权流程的客户端认证转换器，指定其处理的端点路径
		DeviceClientAuthenticationConverter deviceClientAuthenticationConverter = new DeviceClientAuthenticationConverter(
				"/oauth2/device_authorization");
		// 创建对应的认证提供者，用于验证客户端身份
		DeviceClientAuthenticationProvider deviceClientAuthenticationProvider = new DeviceClientAuthenticationProvider(
				registeredClientRepository);

		// 2. 获取授权服务器的默认配置器
		OAuth2AuthorizationServerConfigurer authzConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

		// 3. 开始配置 HttpSecurity
		// 【目的】明确指定这条安全链处理 OAuth2/OIDC 端点 + 登录流程
		http.securityMatcher("/oauth2/authorize", "/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
				"/oauth2/device_authorization", "/oauth2/device/verify", "/oauth2/jwks", "/oauth2/connect/register",
				"/consent", "/logout", "/login.html", "/login",
				"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server").with(
						authzConfigurer, as -> as
								// 3.1 配置授权服务器的各项设置
								.authorizationServerSettings(
										AuthorizationServerSettings.builder().issuer("http://localhost:9000") // 设置发行者标识
												.authorizationEndpoint("/oauth2/authorize") // 授权端点
												.tokenEndpoint("/oauth2/token") // 令牌端点
												.deviceAuthorizationEndpoint("/oauth2/device_authorization")
												.deviceVerificationEndpoint("/oauth2/device/verify")
												.oidcUserInfoEndpoint("/userinfo")
												.oidcClientRegistrationEndpoint("/oauth2/connect/register")
												// OIDC RP-Initiated Logout 端点。
												// OidcLogoutEndpointFilter 的匹配路径设为 /oidc/logout 以避免拦截
												// /logout 请求（/logout 由 LogoutController 处理 partialLogout + 重定向）。
												.oidcLogoutEndpoint("/oidc/logout")
												.build())
								.authorizationEndpoint(endpoint -> endpoint.consentPage("/consent")) // 指定用户同意授权的页面路径
								.clientAuthentication(clientAuth -> clientAuth
										// 【目的】注入自定义的客户端认证组件，以支持设备授权流程
										.authenticationConverter(deviceClientAuthenticationConverter)
										.authenticationProvider(deviceClientAuthenticationProvider))
								.tokenEndpoint(tokenEndpoint -> tokenEndpoint
										// 【目的】深度定制令牌端点的认证逻辑
										.authenticationProviders(providers -> {
											// 移除默认的设备码认证提供者
											providers
													.removeIf(p -> p instanceof OAuth2DeviceCodeAuthenticationProvider);
											// 令牌签发准入策略: 移除默认的授权码/刷新令牌提供者,
											// 换成策略感知包装器 (签发前先做"客户端 × 身份类型"校验)
											providers
													.removeIf(p -> p instanceof OAuth2AuthorizationCodeAuthenticationProvider);
											providers
													.removeIf(p -> p instanceof OAuth2RefreshTokenAuthenticationProvider);
											// 添加自定义的密码模式认证提供者 (内置准入校验)
											providers.add(new PasswordGrantAuthenticationProvider(
													registeredClientRepository, portalUserDetailsService,
													passwordEncoder, authorizationService, tokenGenerator,
													clientUserPolicyService));
											// 添加自定义的设备码认证提供者 (内置准入校验)
											providers.add(new DeviceCodeGrantAuthenticationProvider(
													registeredClientRepository, authorizationService,
													portalUserDetailsService, tokenGenerator,
													clientUserPolicyService));
											// 授权码兑换 / 刷新令牌: 包装 SAS 默认提供者, 带准入策略
											providers.add(new PolicyAwareAuthorizationCodeAuthenticationProvider(
													new OAuth2AuthorizationCodeAuthenticationProvider(
															authorizationService, tokenGenerator),
													clientUserPolicyService, authorizationService));
											providers.add(new PolicyAwareRefreshTokenAuthenticationProvider(
													new OAuth2RefreshTokenAuthenticationProvider(
															authorizationService, tokenGenerator),
													clientUserPolicyService, authorizationService));
										})
										// 【目的】组合多种认证转换器，确保能处理密码模式、授权码、刷新令牌等多种请求
										.accessTokenRequestConverter(new DelegatingAuthenticationConverter(
												List.of(new PasswordGrantAuthenticationConverter(),
														new OAuth2AuthorizationCodeAuthenticationConverter(),
														new OAuth2RefreshTokenAuthenticationConverter(),
														new OAuth2ClientCredentialsAuthenticationConverter(),
														new OAuth2DeviceCodeAuthenticationConverter()))))
								.deviceAuthorizationEndpoint(da -> da.verificationUri("/activate")) // 设置设备验证的用户友好 URI
								.deviceVerificationEndpoint(dv -> dv.consentPage("/consent")) // 设备验证也使用同一个同意页面
								// 【增强】Token Introspection: 替换默认提供者,
								// 保证 Opaque access_token 在授权码等流程下也能内省出 sub/scope/client_id
								// (默认提供者只读取 token 元数据 claims, Opaque 授权码 token 无 claims => sub 缺失)
								.tokenIntrospectionEndpoint(tie -> tie.authenticationProviders(
										providers -> {
											providers.removeIf(
													p -> p instanceof OAuth2TokenIntrospectionAuthenticationProvider);
											providers.add(new EnrichedOAuth2TokenIntrospectionAuthenticationProvider(
													registeredClientRepository, authorizationService));
										}))
								.oidc(Customizer.withDefaults())); // 启用 OIDC 默认配置

		// 4. 注册全局的认证提供者
		// 用于处理普通的表单登录（如 /login 端点）
		http.authenticationProvider(portalDaoProvider)
				// 5. 配置其他安全细节
				.exceptionHandling(ex -> ex
						// 处理未认证的 HTML 请求，重定向到登录页
						.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login.html"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
				.authorizeHttpRequests(auth -> auth
						// 【目的】放行所有 OAuth2 端点和登录页，让请求能到达对应的过滤器进行处理
						.requestMatchers("/login.html", "/login", "/error", "/.well-known/openid-configuration",
								"/.well-known/oauth-authorization-server", "/oauth2/token", "/oauth2/introspect",
								"/oauth2/revoke", "/oauth2/device_authorization", "/oauth2/jwks",
								"/oauth2/connect/register", "/userinfo", "/logout")
						.permitAll()
						// 其他所有请求都需要认证
						.anyRequest().authenticated())
				.formLogin(form -> form.loginPage("/login.html") // 自定义登录页面
						.loginProcessingUrl("/login") // 登录表单提交地址
						.permitAll())
				// 【目的】忽略设备验证端点和登录表单提交的 CSRF 校验
				// /oauth2/device/verify: 跨安全链 CSRF Token 不一致
				// /login POST: login.html 为静态文件, 无服务端渲染的 CSRF token
				.csrf(csrf -> csrf.ignoringRequestMatchers(
						new AntPathRequestMatcher("/oauth2/device/verify"),
						new AntPathRequestMatcher("/login", "POST")))
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
						.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry) // 配置会话注册表
								.maximumSessions(-1) // 允许同一用户并发会话数（-1为不限制）
								.expiredUrl("/login.html?expired"))) // 会话过期后的跳转地址
				.securityContext(sc -> sc.securityContextRepository(
						// 【目的】使用复合的上下文仓库，以支持在同一应用中管理多种不同类型的登录会话
						new CompositeSecurityContextRepository(DEVICE_CONTEXT_KEY, PORTAL_CONTEXT_KEY)))
				// 在 SecurityContextHolderFilter 之后添加自定义的会话过期过滤器
				.addFilterAfter(new SessionExpirationFilter(sessionRegistry), SecurityContextHolderFilter.class)
				// 跟踪当前活跃客户端 (解析 Bearer Token, 存入 Session)
				.addFilterAfter(new ActiveClientTrackingFilter(authorizationService), SecurityContextHolderFilter.class)
				// 【增强】授权端点发码前先做"客户端 × 身份类型"准入:
				// 不合规直接回认证中心登录页 /login.html?error, 不向客户端签发授权码
				// (过滤器内部用 /oauth2/authorize 匹配器限定范围, 不影响令牌等其它端点)
				.addFilterAfter(new AuthorizePolicyFilter(clientUserPolicyService), SecurityContextHolderFilter.class);

		return http.build();
	}

	// ------------------------------------------------------------------
	// 链 2: 管理 REST API 链
	// ------------------------------------------------------------------

	/**
	 * 认证中心管理 REST API 安全链。
	 * <p>
* 保护 {@code /api/admin/**} 四域管理接口（用户 / 客户端 / 会话 / 授权记录）。
 * 仅接受 {@code authserver.admin-client-ids} 白名单内客户端签发的令牌访问，
 * 且令牌主体需具备 {@code ADMIN_SERVICE_TOKEN}（管理服务凭证），实现管理资源的客户端级隔离保护。
 */
	@Bean
	@Order(2)
	public SecurityFilterChain adminApiSecurityFilterChain(HttpSecurity http,
			RedisOpaqueTokenIntrospector redisOpaqueTokenIntrospector) throws Exception {
		// 1. 配置请求匹配与授权规则
		// 【目的】明确指定这条安全链只处理 /api/admin/** 管理接口
		http.securityMatcher("/api/admin/**")
				// 授权决策: 令牌需来自白名单客户端且具备 ADMIN_SERVICE_TOKEN (管理服务凭证)
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/api/admin/**")
						.access(adminAccessManager(authServerProperties.getAdminClientIds())))

				// 2. 配置 OAuth2 资源服务器
				// 【目的】用本地 Redis 自省器校验 Bearer Token, 认证中心不依赖远程 introspection 调用
				.oauth2ResourceServer(rs -> rs.opaqueToken(token -> token.introspector(redisOpaqueTokenIntrospector)))

				// 3. 配置异常处理
				// 【目的】认证/授权失败分别以 JSON 401 / 403 返回, 避免与认证链的登录页跳转冲突
				.exceptionHandling(ex -> ex
						.authenticationEntryPoint((req, res, e) -> {
							res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
							res.setContentType("application/json;charset=UTF-8");
							res.getWriter().write("{\"code\":401,\"msg\":\"未认证或令牌无效\",\"data\":null}");
						})
						.accessDeniedHandler((req, res, e) -> {
							res.setStatus(HttpServletResponse.SC_FORBIDDEN);
							res.setContentType("application/json;charset=UTF-8");
							res.getWriter().write("{\"code\":403,\"msg\":\"无权访问\",\"data\":null}");
						}))

				// 4. 配置 CSRF
				// 【目的】管理接口为 Bearer Token 鉴权, 无会话 Cookie, 禁用 CSRF 防护
				.csrf(csrf -> csrf.disable());
		return http.build();
	}

	// ------------------------------------------------------------------
	// 链 3: 设备验证链
	// ------------------------------------------------------------------

	@Bean
	@Order(3)
	public SecurityFilterChain deviceVerificationSecurityFilterChain(HttpSecurity http,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider,
			SessionRegistry sessionRegistry) throws Exception {

		// 1. 配置请求匹配与认证提供者
		// 【目的】明确指定这条安全链只处理 /activate 和 /device-login 两个端点
		// 【注意】复用了 OAuth2 授权登录的认证提供者，意味着设备验证使用的是普通用户账号体系
		http.securityMatcher("/activate", "/device-login").authenticationProvider(portalDaoProvider)

				// 2. 配置安全上下文与会话管理
				// 【目的】使用独立的 SecurityContext Key，将设备验证流程的会话与普通用户会话隔离
				.securityContext(sc -> sc.securityContextRepository(contextRepo(DEVICE_CONTEXT_KEY)))
				// 【目的】配置会话并发控制，使用全局的 SessionRegistry 跟踪会话
				.sessionManagement(sm -> sm.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry)
						.maximumSessions(-1).expiredUrl("/login.html?expired")))
				// 【注意】在用户名密码过滤器之前添加自定义的会话过期过滤器
				.addFilterBefore(new SessionExpirationFilter(sessionRegistry),
						UsernamePasswordAuthenticationFilter.class)

				// 3. 配置授权规则
				// 【目的】放行设备登录处理端点 /device-login，但要求访问 /activate（设备验证页面）必须已认证
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/device-login").permitAll().anyRequest().authenticated())

				// 4. 配置表单登录
				// 【目的】指定设备验证流程的专属登录页面和处理 URL
				// 登录成功后，会跳转到 /activate 页面，完成设备码与用户账户的绑定
				.formLogin(form -> form.loginPage("/login.html?type=device").loginProcessingUrl("/device-login")
						.defaultSuccessUrl("/activate", false).failureUrl("/login.html?type=device&error").permitAll())

				// 5. 配置 CSRF
				// 【目的】使用基于 Cookie 的 CSRF 令牌策略，并将 HttpOnly 设置为 false，以便前端 JavaScript 可以读取令牌
				// 【注意】特别忽略了对 /device-login 的 POST 请求的 CSRF 校验
				.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
						.ignoringRequestMatchers(new AntPathRequestMatcher("/device-login", "POST")));

		return http.build();
	}

	// ------------------------------------------------------------------
	// 私有辅助方法
	// ------------------------------------------------------------------

/**
 * 管理 API 访问决策：请求令牌需同时满足「客户端在白名单内」且「具备 ADMIN_SERVICE_TOKEN 管理服务凭证」。
 */
private static AuthorizationManager<RequestAuthorizationContext> adminAccessManager(Set<String> adminClientIds) {
    return (authentication, context) -> {
        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> ADMIN_SERVICE_TOKEN.equals(a.getAuthority()));
			if (!isAdmin) {
				return new AuthorizationDecision(false);
			}
			if (auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
				Object clientId = principal.getAttributes().get("client_id");
				if (clientId != null && adminClientIds.contains(clientId.toString())) {
					return new AuthorizationDecision(true);
				}
			}
			return new AuthorizationDecision(false);
		};
	}

	/** 创建使用指定 key 的 HttpSessionSecurityContextRepository，隔离各链路的安全上下文 */
	private static HttpSessionSecurityContextRepository contextRepo(String key) {
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
		repo.setSpringSecurityContextKey(key);
		return repo;
	}

	/**
	 * 允许的 post-logout 重定向目标, 防止 open-redirect 漏洞:
	 * 本站同源路径 (以 / 开头, 不包含 // 协议跳) 或 OAuth2 回调客户端地址。
	 */
	private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of(
			"localhost:8000", "localhost:8080", "localhost:8081", "localhost:8082", "localhost:8083", "localhost:8084", "localhost:9000",
			"127.0.0.1:8000", "127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082", "127.0.0.1:8083", "127.0.0.1:8084", "127.0.0.1:9000"
	);

	/** 检查退出跳转 URL 是否在白名单内（同源路径自动通过） */
	private static boolean isRedirectAllowed(String url) {
		if (url == null || url.isEmpty())
			return false;
		try {
			if (url.startsWith("/") && !url.startsWith("//"))
				return true;
			URI u = URI.create(url);
			String host = u.getHost();
			int port = u.getPort();
			if (host == null)
				return false;
			String key = (port <= 0) ? host : host + ":" + port;
			return ALLOWED_REDIRECT_HOSTS.contains(key);
		} catch (Exception ignore) {
			return false;
		}
	}

	/**
	 * 部分登出: 只移除指定的 SecurityContext 属性, 避免误删同一会话中其他链路的登录态.
	 * <p>
	 * OAuth2 授权登录 (PORTAL)、设备验证 (DEVICE) 共用同一个 HttpSession (共享 JSESSIONID),
	 * SecurityContext 通过不同的 session 属性 key 隔离。若直接 session.invalidate()
	 * 会销毁所有链路的登录态。此方法仅清除本次登出涉及的 context key,
	 * 全部清空时才真正销毁 session, 否则保留其余链路的登录态。
	 */
	public static void partialLogout(SessionRegistry sessionRegistry,
			HttpServletRequest req,
			String... contextKeysToRemove) {
		var session = req.getSession(false);
		if (session == null) {
			SecurityContextHolder.clearContext();
			return;
		}
		for (String key : contextKeysToRemove) {
			session.removeAttribute(key);
		}
		boolean anyLeft = session.getAttribute(DEVICE_CONTEXT_KEY) != null;
		sessionRegistry.removeSessionInformation(session.getId());
		if (!anyLeft) {
			session.invalidate();
		}
		SecurityContextHolder.clearContext();
	}
}