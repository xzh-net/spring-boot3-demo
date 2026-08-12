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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider;
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
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
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
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.authentication.client.DeviceClientAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.DeviceCodeGrantAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.PasswordGrantAuthenticationProvider;
import net.xzh.authserver.security.session.RedisSessionRegistry;
import net.xzh.authserver.security.web.ActiveClientTrackingFilter;
import net.xzh.authserver.security.web.CompositeSecurityContextRepository;
import net.xzh.authserver.security.web.SessionExpirationFilter;
import net.xzh.authserver.security.web.converter.DeviceClientAuthenticationConverter;
import net.xzh.authserver.security.web.converter.PasswordGrantAuthenticationConverter;

/**
 * Spring Authorization Server 核心配置类.
 * <p>
 * 职责：
 * <ol>
 * <li>定义 4 条 SecurityFilterChain，按优先级处理不同的请求路径。</li>
 * <li>配置 OAuth2 授权服务器端点（授权码、设备码、令牌、内省、撤销、JWKS、OIDC）。</li>
 * <li>配置 TokenGenerator 链路：OAuth2AccessTokenGenerator → JwtGenerator，优先 Opaque
 * 格式。</li>
 * <li>注册自定义 AuthenticationProvider（密码授权、设备码授权、设备码客户端认证）。</li>
 * <li>配置客户端认证 Converter 链路，支持 NONE（公共客户端）和 CLIENT_SECRET_BASIC。</li>
 * <li>配置 OIDC UserInfo 和 ClientRegistration 端点。</li>
 * <li>管理安全上下文隔离：OAuth2 授权登录/管理员/设备验证使用独立的 SecurityContext Key。</li>
 * </ol>
 *
 * 4 条 FilterChain 概览：
 * <ul>
 * <li><b>Order(1)</b> — OAuth2 端点 + 登录页（授权、令牌、内省、撤销、设备码、JWKS、OIDC、/login）</li>
 * <li><b>Order(2)</b> — 资源服务器 /api/**（Bearer Token 认证，无状态）</li>
 * <li><b>Order(3)</b> — 管理员后台 /admin/**（独立 UserDetailsService + 表单登录）</li>
 * <li><b>Order(5)</b> — 设备验证 /activate、/device-login（独立 UserDetailsService）</li>
 * </ul>
 * <p>
 * 门户已拆分为独立项目 (portal-app 8000 + portal-server 8080)，通过 OAuth2 授权码流程接入。
 * 认证中心不再包含门户专属安全链，/login 和 /logout 由 Order(1) 链统一处理。
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	/** OAuth2 授权码流程登录态的 SecurityContext 在会话中的属性键（历史命名 PORTAL，实际用于 /login 表单登录会话） */
	public static final String PORTAL_CONTEXT_KEY = "PORTAL_SECURITY_CONTEXT";

	/** 管理员后台的 SecurityContext 在会话中的属性键 */
	static final String ADMIN_CONTEXT_KEY = "ADMIN_SECURITY_CONTEXT";

	/** 设备验证流程的 SecurityContext 在会话中的属性键 */
	static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

	/** OAuth2 令牌的预期受众（用于 introspection 和 UserInfo 的 aud claim） */
	static final String CONTACTS_API_AUD = "contacts-api";

	/** 创建使用指定 key 的 HttpSessionSecurityContextRepository，隔离各链路的安全上下文 */
	private static HttpSessionSecurityContextRepository contextRepo(String key) {
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
		repo.setSpringSecurityContextKey(key);
		return repo;
	}

	/**
	 * 基于 Redis 的 SessionRegistry Bean。
	 * <p>
	 * 使用 {@link RedisSessionRegistry} 将会话跟踪信息持久化到 Redis，
	 * 确保服务器重启后管理端/客户端在线用户列表数据不丢失。
	 * <ul>
	 *   <li>HttpSession 数据通过 Spring Session 持久化到 Redis (登录状态不丢失)</li>
	 *   <li>SessionRegistry 跟踪索引也持久化到 Redis (在线列表不丢失)</li>
	 * </ul>
	 */
	@Bean
	public RedisSessionRegistry sessionRegistry(StringRedisTemplate redisTemplate) {
		log.info("使用 RedisSessionRegistry, 会话跟踪信息持久化到 Redis");
		return new RedisSessionRegistry(redisTemplate);
	}

	/** 将 HttpSession 事件转发给 SessionRegistry，确保会话生命周期正确跟踪 */
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	// ------------------------------------------------------------------
	// 密钥 & 编码器
	// ------------------------------------------------------------------

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

	// ------------------------------------------------------------------
	// DaoAuthenticationProvider（OAuth2 授权登录 + 管理员，各链路按需注入）
	// ------------------------------------------------------------------

	@Bean("portalDaoProvider")
	public DaoAuthenticationProvider portalDaoProvider(
			@Qualifier("portalUserDetailsService") UserDetailsService portalUserDetailsService,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(portalUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

	@Bean("adminDaoProvider")
	public DaoAuthenticationProvider adminDaoProvider(
			@Qualifier("adminUserDetailsService") UserDetailsService adminUserDetailsService,
			PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(adminUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return provider;
	}

	/**
	 * 【关键】设置最高优先级，确保 OAuth2 请求最先被这条链处理
	 */
	@Bean
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			RegisteredClientRepository registeredClientRepository, RedisOAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService, OAuth2TokenGenerator<?> tokenGenerator,
			OpaqueTokenIntrospector introspector,
			@Qualifier("portalUserDetailsService") UserDetailsService portalUserDetailsService,
			PasswordEncoder passwordEncoder,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider,
			SessionRegistry sessionRegistry) throws Exception {

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
		// 【注意】/login.html 和 /login 加入此链: 门户链 (原 Order 6) 删除后,
		//        登录页和表单提交端点需要由本链处理, 否则 formLogin().loginProcessingUrl("/login") 不生效
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
													// OIDC RP-Initiated Logout 端点配置。
													// 注意: 实际的 /logout 由 LogoutController 处理 (partialLogout + 重定向),
													// OidcLogoutEndpointFilter 的匹配路径设为 /oidc/logout 以避免拦截 /logout 请求。
													// OIDC discovery 中的 end_session_endpoint 仍指向 /oidc/logout,
													// 但 portal-server 和各客户端均直接使用 /logout, 不依赖 discovery。
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
											// 添加自定义的密码模式认证提供者
											providers.add(new PasswordGrantAuthenticationProvider(
													registeredClientRepository, portalUserDetailsService,
													passwordEncoder, authorizationService, tokenGenerator));
											// 添加自定义的设备码认证提供者
											providers.add(new DeviceCodeGrantAuthenticationProvider(
													registeredClientRepository, authorizationService,
													portalUserDetailsService, tokenGenerator));
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
								.oidc(Customizer.withDefaults())); // 启用 OIDC 默认配置

		// 4. 注册全局的认证提供者
		// 用于处理普通的表单登录（如 /login 端点）
		http.authenticationProvider(portalDaoProvider);
		// 【目的】注册不透明令牌（Opaque Token）的认证提供者，用于通过 Redis 等方式校验令牌
		http.authenticationProvider(new OpaqueTokenAuthenticationProvider(introspector));

		// 5. 配置其他安全细节
		http.exceptionHandling(ex -> ex
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
				.addFilterAfter(new ActiveClientTrackingFilter(authorizationService), SecurityContextHolderFilter.class);

		return http.build();
	}

	/**
	 * 【关键】设置优先级为 2，仅次于授权服务器端点链，确保 /api/** 请求优先被此链处理
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http,
			OpaqueTokenIntrospector introspector,
			RedisOAuth2AuthorizationService authorizationService) throws Exception {

		// 1. 配置请求匹配与 CSRF
		// 【目的】明确指定这条安全链只处理 /api/** 开头的请求
		// 【注意】RESTful API 通常是无状态的，因此禁用 CSRF 防护
		http.securityMatcher("/api/**").csrf(csrf -> csrf.disable())

				// 2. 配置会话管理
				// 【目的】设置为无状态（STATELESS），Spring Security 不会创建或使用 HttpSession 来存储安全上下文
				// 每次请求都必须携带有效的 Token，服务器端不保留会话状态
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

				// 3. 配置授权规则
				// 【目的】/api/public/** 公开访问 (供 portal-server BFF 调用获取客户端列表)
				// 【目的】其余 /api/** 请求必须经过身份认证
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/api/public/**").permitAll()
						.anyRequest().authenticated())

				// 4. 配置资源服务器
				// 【目的】启用 OAuth2 资源服务器功能，并指定使用“不透明令牌”（Opaque Token）模式
				// 当请求携带 Bearer Token 时，Spring Security 会调用 introspector 去授权服务器校验令牌的有效性
				.oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(opaque -> opaque.introspector(introspector)))
				// 跟踪当前活跃客户端 (解析 Bearer Token, 存入 Session)
				// 虽然资源服务器配置为 STATELESS, 但 ActiveClientTrackingFilter 会主动创建 Session
				.addFilterAfter(new ActiveClientTrackingFilter(authorizationService), SecurityContextHolderFilter.class);

		return http.build();
	}

	/**
	 * 【关键】设置优先级为 3，确保 /admin/** 请求优先被此链处理
	 */
	@Bean
	@Order(3)
	public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http,
			@Qualifier("adminDaoProvider") DaoAuthenticationProvider adminDaoProvider,
			RedisOAuth2AuthorizationService authorizationService,
			SessionRegistry sessionRegistry) throws Exception {

		// 1. 配置请求匹配与认证提供者
		// 【目的】明确指定这条安全链只处理 /admin/** 开头的请求
		// 【注意】注入了专门为管理员配置的 DaoAuthenticationProvider，使用独立的用户详情服务
		http.securityMatcher("/admin/**").authenticationProvider(adminDaoProvider)

				// 2. 配置异常处理
				// 【目的】当未认证的用户访问受保护的管理员页面时，重定向到管理员专属的登录页
				.exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/admin/login.html"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))

				// 3. 配置安全上下文与会话管理
				// 【目的】使用独立的 SecurityContext Key，将管理员会话与普通用户会话隔离
				.securityContext(sc -> sc.securityContextRepository(contextRepo(ADMIN_CONTEXT_KEY)))
				// 【目的】配置会话并发控制，使用全局的 SessionRegistry 跟踪会话，不限制最大会话数
				.sessionManagement(sm -> sm.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry)
						.maximumSessions(-1).expiredUrl("/admin/login.html?expired")))
				// 【注意】在用户名密码过滤器之前添加自定义的会话过期过滤器
				.addFilterBefore(new SessionExpirationFilter(sessionRegistry),
						UsernamePasswordAuthenticationFilter.class)

				// 4. 配置授权规则
				// 【目的】放行管理员登录相关页面，要求所有 /admin/** 请求必须具有 ADMIN 角色
				.authorizeHttpRequests(auth -> auth.requestMatchers("/admin/login.html", "/admin/login", "/admin/error")
						.permitAll().requestMatchers("/admin/**").hasRole("ADMIN"))

				// 5. 配置表单登录
				// 【目的】指定管理员的登录页面、登录处理 URL 以及登录成功/失败后的跳转地址
				.formLogin(form -> form.loginPage("/admin/login.html").loginProcessingUrl("/admin/login")
						.defaultSuccessUrl("/admin", true).failureUrl("/admin/login.html?error").permitAll())

				// 6. 配置登出
				// 【目的】管理员登出时只清理 ADMIN_SECURITY_CONTEXT, 保留同一会话中的 OAuth2/设备登录态
				// 【在线会话同步】同步撤销该管理员通过授权码流程产生的 OAuth2Authorization
				// 【注意】必须显式 .invalidateHttpSession(false).clearAuthentication(false),
				//       否则 LogoutConfigurer 自动注入的 SecurityContextLogoutHandler
				//       会在我们自定义 handler 之前就调用 session.invalidate(), 导致部分登出失效
				.logout(logout -> logout.logoutUrl("/admin/logout")
						.invalidateHttpSession(false)
						.clearAuthentication(false)
						.addLogoutHandler((HttpServletRequest req, HttpServletResponse res, Authentication auth) -> {
							if (auth != null && auth.getName() != null) {
								revokeAuthorizationCodeGrantsForPrincipal(authorizationService, auth.getName());
							}
							partialLogout(sessionRegistry, req, ADMIN_CONTEXT_KEY);
						})
						.logoutSuccessHandler((req, res, auth) -> {
							res.setContentType("application/json;charset=UTF-8");
							res.getWriter().write("{\"authenticated\":false}");
						}).permitAll())

				// 7. 配置 CSRF
				// 【注意】为管理员后台禁用了 CSRF 防护
				.csrf(csrf -> csrf.disable());

		return http.build();
	}

	/**
	 * 允许的 post-logout 重定向目标. 防止 open-redirect 漏洞:
	 *  1. 本站同源路径 (以 / 开头, 不包含 // 协议跳)
	 *  2. OAuth2 回调客户端地址 (http://localhost:8000~8084, http://localhost:9000)
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
	 *
	 * <p>背景: OAuth2 授权登录(PORTAL)、管理员(ADMIN)、设备验证(DEVICE)三条链路共用同一个
	 * HttpSession(都在 localhost:9000, 共享 JSESSIONID cookie),
	 * SecurityContext 通过不同的 session 属性 key 隔离。
	 * 如果直接调用 {@code session.invalidate()} 会销毁所有链路的登录态，
	 * 比如在 8083 客户端 OIDC 登出回调触发 /logout 时，管理员会话也会被连带踢掉。</p>
	 *
	 * <p>处理步骤:</p>
	 * <ol>
	 *   <li>从 session 中移除传入的 contextKeys</li>
	 *   <li>检查 session 中是否还留有其他 SecurityContext 属性
	 *       (ADMIN/DEVICE 之一; PORTAL 登出代表 OAuth2 SSO 终结, 不参与残留检查)</li>
	 *   <li>全部为空时才真正 {@code session.invalidate()} 并通知 SessionRegistry;
	 *       有残留时只清掉指定属性，保留其他链路的登录态</li>
	 * </ol>
	 *
	 * @param sessionRegistry 会话注册表，用于在完全销毁会话时移除 sessionId 跟踪
	 * @param req             当前请求
	 * @param contextKeysToRemove 本次要移除的 SecurityContext session 属性键
	 */
	public static void partialLogout(SessionRegistry sessionRegistry,
									  HttpServletRequest req,
									  String... contextKeysToRemove) {
		var session = req.getSession(false);
		if (session == null) {
			SecurityContextHolder.clearContext();
			return;
		}
		// 1. 移除本次指定的 context keys
		for (String key : contextKeysToRemove) {
			session.removeAttribute(key);
		}
		// 2. 检查 ADMIN/DEVICE 两个 context 键中是否还有任何一个残留
		//    (PORTAL 登出代表 OAuth2 SSO 终结, 不参与残留检查;
		//     残留检查只看 ADMIN/DEVICE, 决定是否保留 session 给其他链路)
		boolean anyLeft = false;
		for (String key : List.of(ADMIN_CONTEXT_KEY, DEVICE_CONTEXT_KEY)) {
			if (session.getAttribute(key) != null) {
				anyLeft = true;
				break;
			}
		}
		// 3. 无论是否还有残留 context, 都从 SessionRegistry 移除当前 session 的跟踪记录
		sessionRegistry.removeSessionInformation(session.getId());
		// 全部清空 → 销毁 session；还有残留 → 只清 SecurityContextHolder, 保留 session
		if (!anyLeft) {
			session.invalidate();
		}
		SecurityContextHolder.clearContext();
	}

	/**
	 * 管理员登出时,同步撤销该用户通过「授权码模式 (authorization_code)」
	 * 产生的所有 OAuth2Authorization 记录。
	 * <p>
	 * 这会让管理后台「在线用户」列表中的对应会话减少或消失,
	 * 因为在线用户列表是基于 Redis 的 oauth2:user:* 索引统计的。
	 * <p>
	 * 只清理 authorization_code 类型的原因:
	 * <ul>
	 *   <li>authorization_code: 完全依赖 OAuth2 SSO 会话,登出=会话终结,必须撤销</li>
	 *   <li>password: 用账号密码直接换 token,不依赖 SSO,不能误删</li>
	 *   <li>device_code / client_credentials: 均为独立流程,不受 SSO 登出影响</li>
	 * </ul>
	 *
	 * @param authorizationService Redis 授权服务,用于查询和删除授权记录
	 * @param principalName        当前登出的用户名
	 */
	private static void revokeAuthorizationCodeGrantsForPrincipal(
			RedisOAuth2AuthorizationService authorizationService,
			String principalName) {
		try {
			int revoked = 0;
			// 遍历该用户名下所有授权记录,只删 authorization_code 类型
			for (OAuth2Authorization auth : authorizationService.findByPrincipal(principalName)) {
				if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(
						auth.getAuthorizationGrantType())) {
					authorizationService.revoke(auth);
					revoked++;
				}
			}
			if (revoked > 0) {
				log.info("[管理员登出] 已撤销 {} 的 {} 条 authorization_code 型 OAuth2 授权",
						principalName, revoked);
			}
		} catch (Exception e) {
			log.warn("[管理员登出] 撤销 authorization_code 授权失败 principal={}: {}",
					principalName, e.getMessage());
		}
	}

	/**
	 * 【关键】设置优先级为 5，确保 /activate 和 /device-login 请求被此链处理
	 */
	@Bean
	@Order(5) 
	public SecurityFilterChain deviceVerificationSecurityFilterChain(HttpSecurity http,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider,
			SessionRegistry sessionRegistry) throws Exception {

		// 1. 配置请求匹配与认证提供者
		// 【目的】明确指定这条安全链只处理 /activate 和 /device-login 两个端点
		// 【注意】复用了 OAuth2 授权登录的认证提供者，意味着设备验证使用的是普通用户账号体系
		http.securityMatcher("/activate", "/device-login").authenticationProvider(portalDaoProvider)

				// 2. 配置安全上下文与会话管理
				// 【目的】使用独立的 SecurityContext Key，将设备验证流程的会话与普通用户、管理员会话隔离
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

	// ====== 已删除: 原 @Order(6) 门户安全链 ======
	// 门户已拆分为独立项目 (portal-app 8000 前端 + portal-server 8080 BFF),
	// 通过 OAuth2 授权码流程接入认证中心。
	// /login 和 /logout 现由 Order(1) 链统一处理, 不再需要独立的门户安全链。
	// 兜底请求 (不匹配 Order 1~5) 由 Spring Security 默认链处理, 返回 401/403。

/**
 * 自定义 Token Customizer: 为 access_token 设置 aud claim, 为 id_token 设置 roles +
	 * preferred_username. 处理两种 principal 类型: UserDetails (授权码) 和
	 * UsernamePasswordAuthenticationToken (密码/刷新).
	 */
	@Bean
	public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
		return context -> {
			String tokenType = context.getTokenType().getValue();
			if ("access_token".equals(tokenType)) {
				context.getClaims().claim("aud", Set.of(CONTACTS_API_AUD));
			}
			if (context.getAuthorization() == null || context.getPrincipal() == null)
				return;
			Object principal = context.getPrincipal();
			String username = null;
			Collection<? extends GrantedAuthority> authorities = List.of();
			if (principal instanceof UserDetails user) {
				username = user.getUsername();
				authorities = user.getAuthorities();
			} else if (principal instanceof UsernamePasswordAuthenticationToken upat) {
				Object inner = upat.getPrincipal();
				if (inner instanceof UserDetails innerUser) {
					username = innerUser.getUsername();
					authorities = innerUser.getAuthorities();
				} else if (inner != null) {
					username = inner.toString();
					authorities = upat.getAuthorities();
				}
			}
			final String userFinal = username;
			final var authFinal = authorities;
			if (userFinal != null) {
				context.getClaims().claims(claims -> {
					claims.put("roles", authFinal.stream().map(a -> a.getAuthority()).toList());
					if ("id_token".equals(tokenType)) {
						claims.put("preferred_username", userFinal);
					}
				});
			}
		};
	}

	/** 全局 TokenSettings: 固定 Opaque 格式, 不允许客户端覆盖 */
	@Bean
	public TokenSettings tokenSettings() {
		return TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE)
				.accessTokenTimeToLive(Duration.ofHours(2)).authorizationCodeTimeToLive(Duration.ofMinutes(5))
				.reuseRefreshTokens(true).build();
	}
}