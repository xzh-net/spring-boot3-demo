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
import org.springframework.security.core.session.SessionRegistryImpl;
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
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.authentication.client.DeviceClientAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.DeviceCodeGrantAuthenticationProvider;
import net.xzh.authserver.security.authentication.grant.PasswordGrantAuthenticationProvider;
import net.xzh.authserver.security.web.CompositeSecurityContextRepository;
import net.xzh.authserver.security.web.SessionExpirationFilter;
import net.xzh.authserver.security.web.converter.DeviceClientAuthenticationConverter;
import net.xzh.authserver.security.web.converter.PasswordGrantAuthenticationConverter;

/**
 * Spring Authorization Server 核心配置类.
 * <p>
 * 职责：
 * <ol>
 * <li>定义 5 条 SecurityFilterChain，按优先级处理不同的请求路径。</li>
 * <li>配置 OAuth2 授权服务器端点（授权码、设备码、令牌、内省、撤销、JWKS、OIDC）。</li>
 * <li>配置 TokenGenerator 链路：OAuth2AccessTokenGenerator → JwtGenerator，优先 Opaque
 * 格式。</li>
 * <li>注册自定义 AuthenticationProvider（密码授权、设备码授权、设备码客户端认证）。</li>
 * <li>配置客户端认证 Converter 链路，支持 NONE（公共客户端）和 CLIENT_SECRET_BASIC。</li>
 * <li>配置 OIDC UserInfo 和 ClientRegistration 端点。</li>
 * <li>管理安全上下文隔离：门户/管理员/设备验证使用独立的 SecurityContext Key。</li>
 * </ol>
 *
 * 5 条 FilterChain 概览：
 * <ul>
 * <li><b>Order(1)</b> — OAuth2 端点（授权、令牌、内省、撤销、设备码、JWKS、OIDC）</li>
 * <li><b>Order(2)</b> — 资源服务器 /api/**（Bearer Token 认证，无状态）</li>
 * <li><b>Order(3)</b> — 管理员后台 /admin/**（独立 UserDetailsService + 表单登录）</li>
 * <li><b>Order(5)</b> — 设备验证 /activate、/device-login（独立
 * UserDetailsService）</li>
 * <li><b>Order(6)</b> — 门户 + 静态资源（表单登录 + 退出 + 白名单重定向）</li>
 * </ul>
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

	/** 门户/授权码流程的 SecurityContext 在会话中的属性键 */
	private static final String PORTAL_CONTEXT_KEY = "PORTAL_SECURITY_CONTEXT";

	/** 管理员后台的 SecurityContext 在会话中的属性键 */
	private static final String ADMIN_CONTEXT_KEY = "ADMIN_SECURITY_CONTEXT";

	/** 设备验证流程的 SecurityContext 在会话中的属性键 */
	private static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

	/** OAuth2 令牌的预期受众（用于 introspection 和 UserInfo 的 aud claim） */
	static final String CONTACTS_API_AUD = "contacts-api";

	/** 创建使用指定 key 的 HttpSessionSecurityContextRepository，隔离各链路的安全上下文 */
	private static HttpSessionSecurityContextRepository contextRepo(String key) {
		HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
		repo.setSpringSecurityContextKey(key);
		return repo;
	}

	/** 跟踪用户 HttpSession，供强制下线时终止 session */
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
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
	// DaoAuthenticationProvider（门户 + 管理员，各链路按需注入）
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
			RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService,
			OAuth2AuthorizationConsentService authorizationConsentService, OAuth2TokenGenerator<?> tokenGenerator,
			OpaqueTokenIntrospector introspector,
			@Qualifier("portalUserDetailsService") UserDetailsService portalUserDetailsService,
			PasswordEncoder passwordEncoder,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider) throws Exception {

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
		// 【目的】明确指定这条安全链只处理列出的这些 OAuth2/OIDC 相关端点
		http.securityMatcher("/oauth2/authorize", "/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
				"/oauth2/device_authorization", "/oauth2/device/verify", "/oauth2/jwks", "/oauth2/connect/register",
				"/consent", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server").with(
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
													// OIDC RP-Initiated Logout 端点：与 Order(6) 链中的自定义 /logout
													// 处理器保持一致，使 OIDC discovery 的 end_session_endpoint
													// 指向 /logout 而非默认的 /connect/logout
													.oidcLogoutEndpoint("/logout")
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
								"/oauth2/connect/register", "/userinfo")
						.permitAll()
						// 其他所有请求都需要认证
						.anyRequest().authenticated())
				.formLogin(form -> form.loginPage("/login.html") // 自定义登录页面
						.loginProcessingUrl("/login") // 登录表单提交地址
						.permitAll())
				// 【目的】忽略设备验证端点的 CSRF 校验，解决跨安全链（从普通业务链到授权服务器链）的 CSRF Token 不一致问题
				.csrf(csrf -> csrf.ignoringRequestMatchers(new AntPathRequestMatcher("/oauth2/device/verify")))
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
						.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry()) // 配置会话注册表
								.maximumSessions(-1) // 允许同一用户并发会话数（-1为不限制）
								.expiredUrl("/login.html?expired"))) // 会话过期后的跳转地址
				.securityContext(sc -> sc.securityContextRepository(
						// 【目的】使用复合的上下文仓库，以支持在同一应用中管理多种不同类型的登录会话
						new CompositeSecurityContextRepository(DEVICE_CONTEXT_KEY, PORTAL_CONTEXT_KEY)))
				// 在 SecurityContextHolderFilter 之后添加自定义的会话过期过滤器
				.addFilterAfter(new SessionExpirationFilter(sessionRegistry()), SecurityContextHolderFilter.class);

		return http.build();
	}

	/**
	 * 【关键】设置优先级为 2，仅次于授权服务器端点链，确保 /api/** 请求优先被此链处理
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http,
			OpaqueTokenIntrospector introspector) throws Exception {

		// 1. 配置请求匹配与 CSRF
		// 【目的】明确指定这条安全链只处理 /api/** 开头的请求
		// 【注意】RESTful API 通常是无状态的，因此禁用 CSRF 防护
		http.securityMatcher("/api/**").csrf(csrf -> csrf.disable())

				// 2. 配置会话管理
				// 【目的】设置为无状态（STATELESS），Spring Security 不会创建或使用 HttpSession 来存储安全上下文
				// 每次请求都必须携带有效的 Token，服务器端不保留会话状态
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

				// 3. 配置授权规则
				// 【目的】要求所有匹配 /api/** 的请求都必须经过身份认证
				.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())

				// 4. 配置资源服务器
				// 【目的】启用 OAuth2 资源服务器功能，并指定使用“不透明令牌”（Opaque Token）模式
				// 当请求携带 Bearer Token 时，Spring Security 会调用 introspector 去授权服务器校验令牌的有效性
				.oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(opaque -> opaque.introspector(introspector)));

		return http.build();
	}

	/**
	 * 【关键】设置优先级为 3，确保 /admin/** 请求优先被此链处理
	 */
	@Bean
	@Order(3)
	public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http,
			@Qualifier("adminDaoProvider") DaoAuthenticationProvider adminDaoProvider,
			RedisOAuth2AuthorizationService authorizationService) throws Exception {

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
				.sessionManagement(sm -> sm.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry())
						.maximumSessions(-1).expiredUrl("/admin/login.html?expired")))
				// 【注意】在用户名密码过滤器之前添加自定义的会话过期过滤器
				.addFilterBefore(new SessionExpirationFilter(sessionRegistry()),
						UsernamePasswordAuthenticationFilter.class)

				// 4. 配置授权规则
				// 【目的】放行管理员登录相关页面，要求所有 /admin/** 请求必须具有 ADMIN 角色
				.authorizeHttpRequests(auth -> auth.requestMatchers("/admin/login.html", "/admin/login", "/admin/error")
						.permitAll().requestMatchers("/admin/**").hasRole("ADMIN"))

				// 5. 配置表单登录
				// 【目的】指定管理员的登录页面、登录处理 URL 以及登录成功/失败后的跳转地址
				.formLogin(form -> form.loginPage("/admin/login.html").loginProcessingUrl("/admin/login")
						.defaultSuccessUrl("/admin/index.html", true).failureUrl("/admin/login.html?error").permitAll())

				// 6. 配置登出
				// 【目的】管理员登出时只清理 ADMIN_SECURITY_CONTEXT, 保留同一会话中的门户/设备登录态
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
							partialLogout(sessionRegistry(), req, ADMIN_CONTEXT_KEY);
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
	 *  2. OAuth2 回调客户端地址 (http://localhost:8080/*)
	 */
	private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of(
			"localhost:8080", "localhost:8081", "localhost:8082", "localhost:8083", "localhost:9000",
			"127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082", "127.0.0.1:8083", "127.0.0.1:9000"
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
	 * <p>背景: 门户(PORTAL)、管理员(ADMIN)、设备验证(DEVICE)三条链路共用同一个
	 * HttpSession(都在 localhost:9000, 共享 JSESSIONID cookie),
	 * SecurityContext 通过不同的 session 属性 key 隔离。
	 * 如果直接调用 {@code session.invalidate()} 会销毁所有链路的登录态，
	 * 比如在 8083 客户端 OIDC 登出回调触发 /logout 时，管理员会话也会被连带踢掉。</p>
	 *
	 * <p>处理步骤:</p>
	 * <ol>
	 *   <li>从 session 中移除传入的 contextKeys</li>
	 *   <li>检查 session 中是否还留有其他 SecurityContext 属性
	 *       (PORTAL/ADMIN/DEVICE 之一)</li>
	 *   <li>全部为空时才真正 {@code session.invalidate()} 并通知 SessionRegistry;
	 *       有残留时只清掉指定属性，保留其他链路的登录态</li>
	 * </ol>
	 *
	 * @param sessionRegistry 会话注册表，用于在完全销毁会话时移除 sessionId 跟踪
	 * @param req             当前请求
	 * @param contextKeysToRemove 本次要移除的 SecurityContext session 属性键
	 */
	private static void partialLogout(SessionRegistry sessionRegistry,
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
		// 2. 检查三个 context 键中是否还有任何一个残留
		boolean anyLeft = false;
		for (String key : List.of(PORTAL_CONTEXT_KEY, ADMIN_CONTEXT_KEY, DEVICE_CONTEXT_KEY)) {
			if (session.getAttribute(key) != null) {
				anyLeft = true;
				break;
			}
		}
		// 3. 全部清空 → 销毁 session；还有残留 → 只清 SecurityContextHolder, 保留 session
		if (!anyLeft) {
			sessionRegistry.removeSessionInformation(session.getId());
			session.invalidate();
		}
		SecurityContextHolder.clearContext();
	}

	/**
	 * 门户/管理员登出时,同步撤销该用户通过「授权码模式 (authorization_code)」
	 * 产生的所有 OAuth2Authorization 记录。
	 * <p>
	 * 这会让管理后台「在线用户」列表中的对应会话减少或消失,
	 * 因为在线用户列表是基于 Redis 的 oauth2:user:* 索引统计的。
	 * <p>
	 * 只清理 authorization_code 类型的原因:
	 * <ul>
	 *   <li>authorization_code: 完全依赖门户/管理员 SSO 会话,登出=会话终结,必须撤销</li>
	 *   <li>password: 用账号密码直接换 token,不依赖门户 SSO,不能误删</li>
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
				log.info("[门户/管理员登出] 已撤销 {} 的 {} 条 authorization_code 型 OAuth2 授权",
						principalName, revoked);
			}
		} catch (Exception e) {
			log.warn("[门户/管理员登出] 撤销 authorization_code 授权失败 principal={}: {}",
					principalName, e.getMessage());
		}
	}

	/**
	 * 【关键】设置优先级为 5，确保 /activate 和 /device-login 请求被此链处理
	 */
	@Bean
	@Order(5) 
	public SecurityFilterChain deviceVerificationSecurityFilterChain(HttpSecurity http,
			@Qualifier("portalDaoProvider") DaoAuthenticationProvider portalDaoProvider) throws Exception {

		// 1. 配置请求匹配与认证提供者
		// 【目的】明确指定这条安全链只处理 /activate 和 /device-login 两个端点
		// 【注意】复用了门户用户的认证提供者，意味着设备验证使用的是普通用户账号体系
		http.securityMatcher("/activate", "/device-login").authenticationProvider(portalDaoProvider)

				// 2. 配置安全上下文与会话管理
				// 【目的】使用独立的 SecurityContext Key，将设备验证流程的会话与普通用户、管理员会话隔离
				.securityContext(sc -> sc.securityContextRepository(contextRepo(DEVICE_CONTEXT_KEY)))
				// 【目的】配置会话并发控制，使用全局的 SessionRegistry 跟踪会话
				.sessionManagement(sm -> sm.sessionConcurrency(sc -> sc.sessionRegistry(sessionRegistry())
						.maximumSessions(-1).expiredUrl("/login.html?expired")))
				// 【注意】在用户名密码过滤器之前添加自定义的会话过期过滤器
				.addFilterBefore(new SessionExpirationFilter(sessionRegistry()),
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

/**
 * 【关键】设置最低优先级，作为“兜底链”（Catch-all）。只有当请求不匹配 Order(1)~Order(5) 的任何路径时，才会落到这里
 */

@Bean
@Order(6)
public SecurityFilterChain portalSecurityFilterChain(
        HttpSecurity http,
        @Qualifier("portalDaoProvider")
        DaoAuthenticationProvider portalDaoProvider,
        RedisOAuth2AuthorizationService authorizationService) throws Exception {

    // 1. 配置认证提供者与安全上下文隔离
    // 【目的】注入门户用户的认证提供者，处理用户名密码登录
    // 【目的】使用独立的 SecurityContext Key (PORTAL_CONTEXT_KEY)，将门户会话与管理员、设备验证会话隔离
    http.authenticationProvider(portalDaoProvider)
            .securityContext(sc -> sc.securityContextRepository(contextRepo(PORTAL_CONTEXT_KEY)))

    // 2. 配置会话管理
    // 【目的】配置会话并发控制，使用全局的 SessionRegistry 跟踪会话，不限制最大会话数 (-1)
    // 【目的】会话过期后重定向到 /login.html?expired
    .sessionManagement(sm -> sm.sessionConcurrency(sc -> sc
            .sessionRegistry(sessionRegistry())
            .maximumSessions(-1)
            .expiredUrl("/login.html?expired")))
    // 【注意】在用户名密码过滤器之前添加自定义的会话过期过滤器，用于实时拦截过期会话
    .addFilterBefore(
            new SessionExpirationFilter(sessionRegistry()),
            UsernamePasswordAuthenticationFilter.class)

    // 3. 配置授权规则
    // 【目的】放行静态资源、登录页、健康检查、Druid/Actuator 监控端点
    // 【目的】放行 /oauth2/device/verify 和 /.well-known/**，确保设备验证和 OIDC 发现端点可公开访问
    // 【目的】/portal 和其余所有请求都需要认证
    .authorizeHttpRequests(auth -> auth
            .requestMatchers(
                    "/", "/login.html", "/portal.html", "/error", "/health", "/health/**",
                    "/druid/**", "/actuator/**",
                    "/css/**", "/js/**", "/images/**", "/favicon.ico",
                    "/oauth2/device/verify", "/.well-known/**",
                    "/userinfo"
            ).permitAll()
            .requestMatchers("/portal").authenticated()
            .anyRequest().authenticated())

    // 4. 配置表单登录
    // 【目的】指定门户登录页面、登录处理 URL 以及登录成功/失败后的跳转地址
    // 【注意】defaultSuccessUrl 的第二个参数 false 表示：如果有原始请求 URL，则跳转到原始 URL，否则跳转到 /portal.html
    .formLogin(form -> form
            .loginPage("/login.html")
            .loginProcessingUrl("/login")
            .defaultSuccessUrl("/portal.html", false)
            .failureUrl("/login.html?error")
            .permitAll())

    // 5. 配置登出 (支持 GET 与 POST)
    // 【目的】支持 GET (OAuth2 客户端 302 跳转) 与 POST (AJAX 退出).
    // 参数: redirect / post_logout_redirect_uri: 退出成功后 302 目标 (经白名单校验)
    // 无合法参数时默认跳回 /login.html
    // 【SSO 隔离】只清理 PORTAL + DEVICE 的 SecurityContext, 保留 ADMIN, 避免
    //            OAuth2 客户端 OIDC 登出回调 /logout 时误把管理员也踢下线
    // 【在线会话同步】门户登出 = SSO 会话结束, 同步撤销该用户所有 authorization_code
    //                grant 产生的 OAuth2Authorization (只清 SSO, 不碰 password/device_code 独立会话)
    // 【注意】必须显式 .invalidateHttpSession(false).clearAuthentication(false),
    //       否则 LogoutConfigurer 自动注入的 SecurityContextLogoutHandler
    //       会在我们自定义 handler 之前就调用 session.invalidate(), 导致部分登出失效
    .logout(logout -> logout
            // 匹配 GET /logout 请求
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .invalidateHttpSession(false)
            .clearAuthentication(false)
            // 登出处理器：
            //   a) 撤销该用户通过门户 SSO 产生的 authorization_code 型授权 → 在线用户-1
            //   b) 仅移除 PORTAL 和 DEVICE 上下文, ADMIN 仍保留
            .addLogoutHandler((HttpServletRequest req, HttpServletResponse res, Authentication auth) -> {
                if (auth != null && auth.getName() != null) {
                    revokeAuthorizationCodeGrantsForPrincipal(authorizationService, auth.getName());
                }
                partialLogout(sessionRegistry(), req, PORTAL_CONTEXT_KEY, DEVICE_CONTEXT_KEY);
            })
            // 登出成功处理器：校验 redirect 参数是否在白名单中，合法则 302 跳转，否则回退到登录页
            .logoutSuccessHandler((req, res, auth) -> {
                String redirect = req.getParameter("redirect");
                if (redirect == null || redirect.isEmpty()) {
                    redirect = req.getParameter("post_logout_redirect_uri");
                }
                String target = isRedirectAllowed(redirect) ? redirect : "/login.html";
                res.setStatus(HttpServletResponse.SC_FOUND);
                res.setHeader("Location", res.encodeRedirectURL(target));
                res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            })
            .permitAll())

    // 6. 配置 CSRF
    // 【目的】使用基于 Cookie 的 CSRF 令牌策略，HttpOnly=false 以便前端 JS 可从 cookie 中读到 XSRF-TOKEN 并作为 header 携带回来
    // 【注意】忽略 /login POST 等表单端点 (原生表单不携带 token)，以及 OAuth2 端点和 /userinfo
    .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                    new AntPathRequestMatcher("/oauth2/token"),
                    new AntPathRequestMatcher("/oauth2/device_authorization"),
                    new AntPathRequestMatcher("/userinfo", "GET"),
                    new AntPathRequestMatcher("/userinfo", "POST"),
                    new AntPathRequestMatcher("/login", "POST")));

    return http.build();
}

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