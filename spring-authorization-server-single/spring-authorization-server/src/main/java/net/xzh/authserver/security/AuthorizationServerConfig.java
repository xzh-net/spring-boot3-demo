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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
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
 *   <li>定义 5 条 SecurityFilterChain，按优先级处理不同的请求路径。</li>
 *   <li>配置 OAuth2 授权服务器端点（授权码、设备码、令牌、内省、撤销、JWKS、OIDC）。</li>
 *   <li>配置 TokenGenerator 链路：OAuth2AccessTokenGenerator → JwtGenerator，优先 Opaque 格式。</li>
 *   <li>注册自定义 AuthenticationProvider（密码授权、设备码授权、设备码客户端认证）。</li>
 *   <li>配置客户端认证 Converter 链路，支持 NONE（公共客户端）和 CLIENT_SECRET_BASIC。</li>
 *   <li>配置 OIDC UserInfo 和 ClientRegistration 端点。</li>
 *   <li>管理安全上下文隔离：门户/管理员/设备验证使用独立的 SecurityContext Key。</li>
 * </ol>
 *
 * 5 条 FilterChain 概览：
 * <ul>
 *   <li><b>Order(1)</b> — OAuth2 端点（授权、令牌、内省、撤销、设备码、JWKS、OIDC）</li>
 *   <li><b>Order(2)</b> — 资源服务器 /api/**（Bearer Token 认证，无状态）</li>
 *   <li><b>Order(3)</b> — 管理员后台 /admin/**（独立 UserDetailsService + 表单登录）</li>
 *   <li><b>Order(5)</b> — 设备验证 /activate、/device-login（独立 UserDetailsService）</li>
 *   <li><b>Order(6)</b> — 门户 + 静态资源（表单登录 + 退出 + 白名单重定向）</li>
 * </ul>
 */
@Slf4j
@Configuration
@EnableWebSecurity
public final class AuthorizationServerConfig {

    /** 门户/授权码流程的 SecurityContext 在会话中的属性键 */
    private static final String PORTAL_CONTEXT_KEY = "PORTAL_SECURITY_CONTEXT";

    /** 管理员后台的 SecurityContext 在会话中的属性键 */
    private static final String ADMIN_CONTEXT_KEY  = "ADMIN_SECURITY_CONTEXT";

    /** 设备验证流程的 SecurityContext 在会话中的属性键 */
    private static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

    /** OAuth2 令牌的预期受众（用于 introspection 和 UserInfo 的 aud claim） */
    static final String CONTACTS_API_AUD = "contacts-api";

    /**
     * 创建使用指定 key 的 HttpSessionSecurityContextRepository。
     * 每个链路使用独立的 key 隔离安全上下文，防止会话污染。
     */
    private static HttpSessionSecurityContextRepository contextRepo(String key) {
        HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
        repo.setSpringSecurityContextKey(key);
        return repo;
    }

    /**
     * SessionRegistry: 跟踪用户 HttpSession, 供强制下线时通过 expireNow() 终止 session.
     * 配合 sessionConcurrency 使用, ConcurrentSessionFilter 会在下次请求时检测到过期并强制重新登录.
     */
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * HttpSessionEventPublisher: 将 HttpSession 创建/销毁事件转发给 SessionRegistry,
     * 使 SessionRegistry 能正确跟踪 session 生命周期 (无此 bean 则 session 超时不会从 registry 移除).
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    // ------------------------------------------------------------------
    // Keys
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
        return (jwkSelector, securityContext) ->
                jwkSelector.select(new JWKSet(List.of(rsaKey, ecKey)));
    }

    @Bean
    @Primary
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder decoder = (NimbusJwtDecoder) OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        // 仅用于 id_token 校验 (默认 issuer + exp). access_token 是 Opaque, 不走 JwtDecoder.
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("http://localhost:9000"));
        return decoder;
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        // 修复 SAS 1.4.1 行为差异: JwtGenerator.supports() 对 access_token 不检查
        // TokenSettings.accessTokenFormat, 直接返回 true, 会导致 access_token 被其抢占生成 JWT.
        // 解决: 将 OAuth2AccessTokenGenerator (opaque) 放在 JwtGenerator 前面,
        // 使其优先处理 access_token. id_token 仍由 JwtGenerator 处理
        // (OAuth2AccessTokenGenerator 不支持 id_token 类型, 会 fallback 到 jwtGenerator).
        // 项目全局固定使用 opaque token, 不允许客户端覆盖此配置.
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                accessTokenGenerator, jwtGenerator, new OAuth2RefreshTokenGenerator());
    }

    // ------------------------------------------------------------------
    // 两套 DaoAuthenticationProvider（门户 + 管理员）
    // 各 SecurityFilterChain 通过 http.authenticationProvider() 直接注入
    // ------------------------------------------------------------------

    @Bean("portalDaoProvider")
    public DaoAuthenticationProvider portalDaoProvider(
            @Qualifier("portalUserDetailsService")
            UserDetailsService portalUserDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(portalUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean("adminDaoProvider")
    public DaoAuthenticationProvider adminDaoProvider(
            @Qualifier("adminUserDetailsService")
            UserDetailsService adminUserDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    // ------------------------------------------------------------------
    // 1. OAuth2 / OIDC 端点链 (最高优先级) — 走门户认证
    // ------------------------------------------------------------------

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            OAuth2AuthorizationConsentService authorizationConsentService,
            OAuth2TokenGenerator<?> tokenGenerator,
            OpaqueTokenIntrospector introspector,
            @Qualifier("portalUserDetailsService")
            UserDetailsService portalUserDetailsService,
            PasswordEncoder passwordEncoder,
            @Qualifier("portalDaoProvider")
            DaoAuthenticationProvider portalDaoProvider) throws Exception {

        // 此处不使用 applyDefaultSecurity, 而是手动构建 OAuth2AuthorizationServerConfigurer,
        // 原因: SAS 1.4 的 oidc(Customizer.withDefaults()) 内部会注册 JwtAuthenticationProvider
        // 用于校验 Bearer token (默认假设 access_token 是 JWT). 我们 access_token 是 Opaque,
        // 需要额外注册 OpaqueTokenAuthenticationProvider 覆盖之, 让 BearerTokenAuthenticationFilter
        // 走 Redis introspect 而非 JWT 验签.
        // ProviderManager 按顺序尝试: Opaque 先认证 (本服务所有 access_token 都能命中),

        // 设备码 public client (认证方法 NONE) 认证组件:
        // device-app 无 client_secret, 需自定义 converter/provider 从请求参数提取 client_id
        String deviceAuthorizationEndpoint = "/oauth2/device_authorization";
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(deviceAuthorizationEndpoint);
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);
        // JWT provider 作为兜底 (用于 id_token 直接作为 Bearer 调用 /userinfo 的兼容场景).
        OAuth2AuthorizationServerConfigurer authzConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        // 使用显式的请求匹配器替代 getEndpointsMatcher(),
        // 确保 OAuth2 端点能被正确路由到此过滤器链.
        // 注意: 必须包含 /.well-known/** 两个发现端点, 否则 SAS 内置的
        // OidcProviderConfigurationEndpointFilter /
        // OAuth2AuthorizationServerMetadataEndpointFilter 不会处理这些请求 → 404
        http.securityMatcher(
                "/oauth2/authorize",
                "/oauth2/token",
                "/oauth2/introspect",
                "/oauth2/revoke",
                "/oauth2/device_authorization",
                "/oauth2/device/verify",
                "/oauth2/jwks",
                "/oauth2/connect/register",
                "/consent",
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server"
        ).with(authzConfigurer, as -> as
                        .authorizationServerSettings(AuthorizationServerSettings.builder()
                                .issuer("http://localhost:9000")
                                .authorizationEndpoint("/oauth2/authorize")
                                .tokenEndpoint("/oauth2/token")
                                .deviceAuthorizationEndpoint("/oauth2/device_authorization")
                                .deviceVerificationEndpoint("/oauth2/device/verify")
                                .oidcUserInfoEndpoint("/userinfo")
                                .oidcClientRegistrationEndpoint("/oauth2/connect/register")
                                .build())
                        .authorizationEndpoint(endpoint -> endpoint
                                .consentPage("/consent"))
                        .clientAuthentication(clientAuth -> clientAuth
                                .authenticationConverter(deviceClientAuthenticationConverter)
                                .authenticationProvider(deviceClientAuthenticationProvider))
                        .tokenEndpoint(tokenEndpoint -> tokenEndpoint
                                .authenticationProviders(providers -> {
                                    // 替换 SAS 默认 OAuth2DeviceCodeAuthenticationProvider, 增加自定义实现以支持 OIDC id_token.
                                    // SAS 默认 Provider 只签发 access_token + refresh_token, 不生成 id_token.
                                    providers.removeIf(p -> p instanceof
                                            OAuth2DeviceCodeAuthenticationProvider);
                                    providers.add(new PasswordGrantAuthenticationProvider(
                                            registeredClientRepository,
                                            portalUserDetailsService,
                                            passwordEncoder,
                                            authorizationService,
                                            tokenGenerator));
                                    providers.add(new DeviceCodeGrantAuthenticationProvider(
                                            registeredClientRepository,
                                            authorizationService,
                                            portalUserDetailsService,
                                            tokenGenerator));
                                })
                                // 注意: accessTokenRequestConverter() 是"替换"而非"追加",
                                // 直接传 PasswordGrantAuthenticationConverter 会覆盖 SAS 默认的
                                // DelegatingAuthenticationConverter (含 OAuth2RefreshTokenAuthenticationConverter /
                                // OAuth2AuthorizationCodeAuthenticationConverter 等), 导致 grant_type=refresh_token
                                // 时无 converter 处理 → OAuth2TokenEndpointFilter 抛 invalid_grant.
                                // 修复: 用 DelegatingAuthenticationConverter 组合自定义 password converter + SAS 默认 converters.
                                .accessTokenRequestConverter(
                                        new DelegatingAuthenticationConverter(
                                                List.of(
                                                        new PasswordGrantAuthenticationConverter(),
                                                        new OAuth2AuthorizationCodeAuthenticationConverter(),
                                                        new OAuth2RefreshTokenAuthenticationConverter(),
                                                        new OAuth2ClientCredentialsAuthenticationConverter(),
                                                        new OAuth2DeviceCodeAuthenticationConverter()))))
                        .deviceAuthorizationEndpoint(da -> da
                                .verificationUri("/activate"))
                        // 设备码 consent 页面: 与 authorizationEndpoint 共用 /consent.
                        // consentPage 只告诉 SAS "consent 页面在哪", 是否弹 consent 仍由
                        // RegisteredClient.clientSettings.requireAuthorizationConsent 决定.
                        // device-app = false → 跳过; 其他设备客户端 = true → 弹 /consent.
                        .deviceVerificationEndpoint(dv -> dv
                                .consentPage("/consent"))
                        .oidc(Customizer.withDefaults()));

        http.authenticationProvider(portalDaoProvider);

        // 给 SAS 链注册 OpaqueTokenAuthenticationProvider, 让 BearerTokenAuthenticationFilter
        // 走 Redis introspect 校验 access_token (本服务所有客户端的 access_token 均为 Opaque).
        // SAS oidc(withDefaults()) 已内置 JwtAuthenticationProvider, 作为 id_token 兜底校验.
        http.authenticationProvider(
                new OpaqueTokenAuthenticationProvider(introspector));

        http.exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login.html"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login.html", "/login", "/error",
                                "/.well-known/openid-configuration",
                                "/.well-known/oauth-authorization-server",
                                // POST 类端点过滤器在 AuthorizationFilter 之后,
                                // public client (无密钥) 不会触发 OAuth2ClientAuthenticationFilter,
                                // 需 permitAll 让请求到达各自端点过滤器, 由它们自行认证
                                "/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                                "/oauth2/device_authorization", "/oauth2/jwks",
                                "/oauth2/connect/register", "/userinfo").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/login")
                        .permitAll())
                // /activate 在 Order(4) 渲染 (CookieCsrfTokenRepository), 表单提交到 Order(1) 的
                // /oauth2/device/verify (默认 HttpSessionCsrfTokenRepository), 跨链 CSRF token 不匹配.
                // 设备验证端点安全性由 SAS 内部保证 (user_code 验证 + 用户登录), 忽略 CSRF.
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        new AntPathRequestMatcher("/oauth2/device/verify")))
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionConcurrency(sc -> sc
                                .sessionRegistry(sessionRegistry())
                                .maximumSessions(-1)
                                .expiredUrl("/login.html?expired")))
                .securityContext(sc -> sc.securityContextRepository(
                        new CompositeSecurityContextRepository(
                                DEVICE_CONTEXT_KEY, PORTAL_CONTEXT_KEY)))
                .addFilterAfter(
                        new SessionExpirationFilter(sessionRegistry()),
                        SecurityContextHolderFilter.class);
        // RedisOAuth2AuthorizationService.save() 检测到后直接 remove() 删 Redis key,
        // 资源服务器 introspect 查不到即返回 401, 无需额外的清理过滤器.

        return http.build();
    }

    // ------------------------------------------------------------------
    // 2. Resource Server 链 (/api/**) — Opaque Token introspect
    //    必须在 portal catch-all 之前匹配, 否则 /api/** 会被 Order(4) 吃掉
    // ------------------------------------------------------------------

    @Bean
    @Order(2)
    public SecurityFilterChain resourceServerSecurityFilterChain(
            HttpSecurity http,
            OpaqueTokenIntrospector introspector) throws Exception {

        http.securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .opaqueToken(opaque -> opaque.introspector(introspector)));

        return http.build();
    }

    // ------------------------------------------------------------------
    // 3. Admin 管理后台链 (/admin/**) — 管理员认证
    // ------------------------------------------------------------------

    @Bean
    @Order(3)
    public SecurityFilterChain adminSecurityFilterChain(
            HttpSecurity http,
            @Qualifier("adminDaoProvider")
            DaoAuthenticationProvider adminDaoProvider) throws Exception {

        http.securityMatcher("/admin/**")
                .authenticationProvider(adminDaoProvider)
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/admin/login.html"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .securityContext(sc -> sc.securityContextRepository(contextRepo(ADMIN_CONTEXT_KEY)))
                .sessionManagement(sm -> sm.sessionConcurrency(sc -> sc
                        .sessionRegistry(sessionRegistry())
                        .maximumSessions(-1)
                        .expiredUrl("/admin/login.html?expired")))
                .addFilterBefore(
                        new SessionExpirationFilter(sessionRegistry()),
                        UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login.html", "/admin/login", "/admin/error").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN"))
                .formLogin(form -> form
                        .loginPage("/admin/login.html")
                        .loginProcessingUrl("/admin/login")
                        .defaultSuccessUrl("/admin/index.html", true)
                        .failureUrl("/admin/login.html?error")
                        .permitAll())
                .logout(logout -> logout
                        .logoutUrl("/admin/logout")
                        .addLogoutHandler((HttpServletRequest req, HttpServletResponse res, Authentication auth) -> {
                            // 彻底销毁 HttpSession (而非仅移除属性), 避免旧 JSESSIONID 触发会话复用
                            var session = req.getSession(false);
                            if (session != null) {
                                sessionRegistry().removeSessionInformation(session.getId());
                                session.invalidate();
                            }
                            SecurityContextHolder.clearContext();
                        })
                        .logoutSuccessHandler((req, res, auth) -> {
                            res.setContentType("application/json;charset=UTF-8");
                            res.getWriter().write("{\"authenticated\":false}");
                        })
                        .permitAll())
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    /**
     * 门户链 (Order 6) 允许的退出跳转目标白名单：
     * 1. 本站同源路径 (以 / 开头, 不包含 // 协议跳)
     * 2. OAuth2 回调客户端地址 (http://localhost:8080/*)
     *    注意：此处使用硬编码白名单，而非读取客户端配置的 postLogoutRedirectUris，
     *    因为 SAS 原生 RP-Initiated Logout 流程未在本项目中启用。
     */
    private static final Set<String> ALLOWED_REDIRECT_HOSTS = Set.of(
            "localhost:8080", "localhost:8081", "localhost:8082", "localhost:9000",
            "127.0.0.1:8080", "127.0.0.1:8081", "127.0.0.1:8082", "127.0.0.1:9000"
    );

    /**
     * 检查给定 URL 是否在允许的退出跳转白名单内。
     * 同源路径（以 / 开头）自动通过；其他 URL 需匹配白名单中的 host:port。
     */
    private static boolean isRedirectAllowed(String url) {
        if (url == null || url.isEmpty()) return false;
        try {
            if (url.startsWith("/") && !url.startsWith("//")) return true; // 同源路径
            URI u = URI.create(url);
            String host = u.getHost();
            int port = u.getPort();
            if (host == null) return false;
            String key = (port <= 0) ? host : host + ":" + port;
            return ALLOWED_REDIRECT_HOSTS.contains(key);
        } catch (Exception ignore) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // 5. 设备验证链 (/activate, /device-login) — 独立认证, 不污染门户会话
    //    用户通过 /device-login 登录后, 认证态存入 DEVICE_SECURITY_CONTEXT.
    //    OAuth2 链 (Order 1) 通过 CompositeSecurityContextRepository 读取此 key.
    //    验证完成后 DeviceActivateController 清除 DEVICE_SECURITY_CONTEXT, 不残留登录态.
    // ------------------------------------------------------------------

    @Bean
    @Order(5)
    public SecurityFilterChain deviceVerificationSecurityFilterChain(
            HttpSecurity http,
            @Qualifier("portalDaoProvider")
            DaoAuthenticationProvider portalDaoProvider) throws Exception {

        http.securityMatcher("/activate", "/device-login")
                .authenticationProvider(portalDaoProvider)
                .securityContext(sc -> sc.securityContextRepository(contextRepo(DEVICE_CONTEXT_KEY)))
                .sessionManagement(sm -> sm.sessionConcurrency(sc -> sc
                        .sessionRegistry(sessionRegistry())
                        .maximumSessions(-1)
                        .expiredUrl("/login.html?expired")))
                .addFilterBefore(
                        new SessionExpirationFilter(sessionRegistry()),
                        UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/device-login").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login.html?type=device")
                        .loginProcessingUrl("/device-login")
                        .defaultSuccessUrl("/activate", false)
                        .failureUrl("/login.html?type=device&error")
                        .permitAll())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(new AntPathRequestMatcher("/device-login", "POST")));

        return http.build();
    }

    // ------------------------------------------------------------------
    // 6. 门户 + 静态资源链 (兜底) — 走门户认证
    // ------------------------------------------------------------------

    @Bean
    @Order(6)
    public SecurityFilterChain portalSecurityFilterChain(
            HttpSecurity http,
            @Qualifier("portalDaoProvider")
            DaoAuthenticationProvider portalDaoProvider) throws Exception {

        http.authenticationProvider(portalDaoProvider)
                .securityContext(sc -> sc.securityContextRepository(contextRepo(PORTAL_CONTEXT_KEY)))
                .sessionManagement(sm -> sm.sessionConcurrency(sc -> sc
                        .sessionRegistry(sessionRegistry())
                        .maximumSessions(-1)
                        .expiredUrl("/login.html?expired")))
                .addFilterBefore(
                        new SessionExpirationFilter(sessionRegistry()),
                        UsernamePasswordAuthenticationFilter.class)
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
                .formLogin(form -> form
                        .loginPage("/login.html")
                        .loginProcessingUrl("/login")
                        .defaultSuccessUrl("/portal.html", false)
                        .failureUrl("/login.html?error")
                        .permitAll())
                // 支持 GET (OAuth2 客户端 302 跳转) 与 POST (AJAX 退出). 参数:
                //   - redirect / post_logout_redirect_uri: 退出成功后 302 目标 (经白名单校验)
                // 无合法参数时默认跳回 /login.html
                .logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .addLogoutHandler((HttpServletRequest req, HttpServletResponse res, Authentication auth) -> {
                            // 彻底销毁 HttpSession: 让 JSESSIONID 失效, 防止客户端再次 /oauth2/authorize 时被自动登录
                            var session = req.getSession(false);
                            if (session != null) {
                                sessionRegistry().removeSessionInformation(session.getId());
                                session.invalidate();
                            }
                            SecurityContextHolder.clearContext();
                        })
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

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            String tokenType = context.getTokenType().getValue();
            if ("access_token".equals(tokenType)) {
                context.getClaims().claim("aud", Set.of(CONTACTS_API_AUD));
            }
            if (context.getAuthorization() == null || context.getPrincipal() == null) return;
            Object principal = context.getPrincipal();
            String username = null;
            Collection<? extends GrantedAuthority> authorities = List.of();
            // 授权码模式: principal 是 UserDetails (DaoAuthenticationProvider 返回的)
            if (principal instanceof UserDetails user) {
                username = user.getUsername();
                authorities = user.getAuthorities();
            }
            // 密码模式 / refresh: principal 是 UsernamePasswordAuthenticationToken,
            // 其 principal 字段存的是 username String
            else if (principal instanceof UsernamePasswordAuthenticationToken upat) {
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
                    claims.put("roles", authFinal.stream()
                            .map(a -> a.getAuthority()).toList());
                    if ("id_token".equals(tokenType)) {
                        claims.put("preferred_username", userFinal);
                    }
                });
            }
        };
    }

    @Bean
    public TokenSettings tokenSettings() {
        // 全局固定使用 opaque token (REFERENCE), 不允许客户端覆盖.
        // 项目资源服务器 / userinfo / /api/** 均基于 RedisOpaqueTokenIntrospector 实现,
        // 切换为 SELF_CONTAINED (JWT) 会导致 introspect 失败返回 401.
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                .accessTokenTimeToLive(Duration.ofHours(2))
                .authorizationCodeTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(true)
                .build();
    }
}
