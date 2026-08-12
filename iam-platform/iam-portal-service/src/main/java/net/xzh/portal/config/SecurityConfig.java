package net.xzh.portal.config;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Spring Security 6 + OAuth2 Client 安全配置.
 *
 * <p>iam-portal-service 作为 BFF (Backend For Frontend)，职责：</p>
 * <ul>
 *   <li>处理 OAuth2 授权码登录流程（持有 client_secret）</li>
 *   <li>提供 REST API 给 iam-portal-web 前端 (8000) 调用</li>
 *   <li>管理 HttpSession，存储 OAuth2 token</li>
 *   <li>登出时通过 OIDC RP-Initiated Logout 通知认证中心</li>
 * </ul>
 *
 * <p><b>SSO 会话隔离：</b>本应用（8080）与授权服务器（9000）同在 localhost，
 * 通过 {@code server.servlet.session.cookie.name=PORTAL_SERVER_SESSION} 设置独立 cookie 名称，
 * 避免与 9000 的 JSESSIONID 冲突。</p>
 *
 * <p><b>登出流程：</b>iam-portal-web 前端通过 302 GET 重定向到 /api/auth/logout,
 * Spring Security LogoutFilter 清除本地 HttpSession 后, 由自定义 LogoutSuccessHandler
 * 携带 id_token_hint 和 post_logout_redirect_uri 跳转到认证中心 /logout 端点,
 * 认证中心清除 SSO 会话后重定向回前端 /logged-out 页面。</p>
 *
 * <p><b>PKCE 支持（设计文档 §4）：</b>虽然 portal-app 是 Confidential Client (client_secret_basic),
 * 但在注册时已设置 requireProofKey=true. 因此本配置通过自定义
 * OAuth2AuthorizationRequestResolver 和 token 请求参数转换器,
 * 主动在授权请求中带 code_challenge=S256(sha256(code_verifier)),
 * 换 token 时带 code_verifier 明文, 符合 RFC 7636.</p>
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Value("${portal.frontend-origin}")
    private String frontendOrigin;

    /** 认证中心 OIDC end_session_endpoint (application.yml 中 logout-uri 配置项) */
    @Value("${spring.security.oauth2.client.provider.spring-auth-server.logout-uri}")
    private String authServerLogoutUri;

    /** PKCE code_verifier 生成器: 32 字节随机数, Base64URL 编码 = 43 字符 (符合 RFC 7636 43~128 要求) */
    private static final StringKeyGenerator CODE_VERIFIER_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

    /**
     * 设计文档 §4.1: 构造带 PKCE 的 OAuth2 授权请求.
     * <p>
     * 对每个授权请求:
     *   1. 生成 code_verifier (一次性随机值)
     *   2. 计算 code_challenge = base64url(sha256(code_verifier))
     *   3. 把 code_verifier 存入 OAuth2AuthorizationRequest 的 additionalParameters,
     *      它会自动保存到 HttpSession 的 OAuth2_AUTHORIZATION_REQUEST_ATTR_NAME 中,
     *      回调时可取出用于换 token.
     */
    @Bean
    public OAuth2AuthorizationRequestResolver pkceAuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver delegate =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository,
                        "/oauth2/authorization");
        delegate.setAuthorizationRequestCustomizer(builder -> {
            String codeVerifier = CODE_VERIFIER_GENERATOR.generateKey();
            String codeChallenge = computeS256CodeChallenge(codeVerifier);
            builder.additionalParameters(params -> {
                // 存 code_verifier 到附加参数, 回调时取出
                params.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
            });
            builder.parameters(params -> {
                // 授权请求参数: code_challenge + code_challenge_method=S256
                params.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                params.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            });
        });
        return delegate;
    }

    /**
     * 设计文档 §4.3: 构造带 PKCE code_verifier 的 AccessToken 请求.
     * <p>
     * Spring Security 默认的 OAuth2AuthorizationCodeGrantRequestEntityConverter 会带上
     * client_secret (client_secret_basic 的客户端). 这里扩展: 从 OAuth2AuthorizationExchange
     * (即从 session 中取出的授权请求) 的 additionalParameters 中读取 code_verifier,
     * 拼到 token 请求表单中.
     */
    @Bean
    public DefaultAuthorizationCodeTokenResponseClient pkceTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        OAuth2AuthorizationCodeGrantRequestEntityConverter delegate =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        delegate.addParametersConverter(grantRequest -> {
            Map<String, String> params = new HashMap<>();
            // 从 session 中保存的 authorizationRequest 附加参数里取出 code_verifier
            Object codeVerifier = grantRequest.getAuthorizationExchange()
                    .getAuthorizationRequest()
                    .getAdditionalParameters()
                    .get(PkceParameterNames.CODE_VERIFIER);
            if (codeVerifier != null) {
                params.put(PkceParameterNames.CODE_VERIFIER, codeVerifier.toString());
            }
            MultiValueMap<String, String> mv = new org.springframework.util.LinkedMultiValueMap<>();
            params.forEach(mv::add);
            return mv;
        });
        client.setRequestEntityConverter(delegate);
        return client;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   OAuth2AuthorizationRequestResolver pkceAuthorizationRequestResolver,
                                                   DefaultAuthorizationCodeTokenResponseClient pkceTokenResponseClient) throws Exception {
        http
                // CORS: 允许 iam-portal-web 前端 (8000) 跨域调用
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 静态资源、健康检查放行 (前后端分离, 无页面)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/error", "/actuator/**",
                                "/css/**", "/js/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                // OAuth2 登录：未认证请求会被重定向到授权服务器 /oauth2/authorize
                .oauth2Login(oauth2Login -> oauth2Login
                        // 设计文档 §4: 使用自定义 PKCE AuthorizationRequestResolver
                        .authorizationEndpoint(ae -> ae.authorizationRequestResolver(pkceAuthorizationRequestResolver))
                        // 设计文档 §4: 使用自定义 PKCE AccessToken 请求客户端
                        .tokenEndpoint(te -> te.accessTokenResponseClient(pkceTokenResponseClient))
                        .loginPage("/oauth2/authorization/portal-app-oidc")
                        .defaultSuccessUrl("/api/auth/callback-success", true))
                .logout(logout -> logout
                        // 1. 支持 GET 请求登出 (iam-portal-web 前端通过 302 重定向到此 URL)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/api/auth/logout", "GET"))
                        // 2. 自定义登出成功处理器: 手动构建 OIDC RP-Initiated Logout URL
                        .logoutSuccessHandler(portalLogoutSuccessHandler()));
        return http.build();
    }

    /**
     * 自定义 OIDC RP-Initiated Logout 成功处理器.
     * <p>
     * <b>为什么不使用 OidcClientInitiatedLogoutSuccessHandler:</b>
     * Spring Security 6.4 的 OidcClientInitiatedLogoutSuccessHandler.determineTargetUrl()
     * 通过 {@code providerDetails.getConfigurationMetadata().get("end_session_endpoint")}
     * 获取 end_session_endpoint, 而 application.yml 中的 logout-uri 配置项不会被映射到
     * 该 metadata key (仅通过 OIDC discovery 才会填充). 当 end_session_endpoint 为 null 时,
     * handler 回退到 SimpleUrlLogoutSuccessHandler 默认行为 (跳到 /), 触发 OAuth2 重新登录循环.
     * <p>
     * <b>本处理器的逻辑:</b>
     * <ol>
     *   <li>从 OidcUser 中提取 id_token (JWT 原文)</li>
     *   <li>构建认证中心 /logout URL, 携带 id_token_hint 和 post_logout_redirect_uri</li>
     *   <li>302 重定向到认证中心, 由 OidcLogoutEndpointFilter 清除 SSO 会话</li>
     *   <li>认证中心验证 post_logout_redirect_uri 后, 302 重定向回前端 /logged-out 页面</li>
     * </ol>
     */
    private LogoutSuccessHandler portalLogoutSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response,
                org.springframework.security.core.Authentication authentication) -> {
            String postLogoutRedirectUri = frontendOrigin + "/logged-out";
            StringBuilder url = new StringBuilder(authServerLogoutUri);
            url.append("?post_logout_redirect_uri=")
                    .append(URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8));

            // 携带 id_token_hint, 使认证中心能识别客户端并验证 post_logout_redirect_uri
            if (authentication != null && authentication.getPrincipal() instanceof OidcUser oidcUser) {
                String idTokenValue = oidcUser.getIdToken().getTokenValue();
                url.append("&id_token_hint=")
                        .append(URLEncoder.encode(idTokenValue, StandardCharsets.UTF_8));
            }

            response.sendRedirect(url.toString());
        };
    }

    /**
     * CORS 配置: 允许 iam-portal-web 前端 (8000) 跨域调用本服务 (8080) 的 API。
     * 允许携带 Cookie (credentials), 支持会话认证。
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(frontendOrigin));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // ========================================================================
    // PKCE 辅助方法 (RFC 7636)
    // ========================================================================

    /**
     * RFC 7636 §4.6 code_challenge = BASE64URL( SHA256( ASCII(code_verifier) ) ).
     */
    private static String computeS256CodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // JVM 规范强制支持 SHA-256, 理论上不会发生
            throw new IllegalStateException("JVM 缺少 SHA-256 MessageDigest 实现", e);
        }
    }
}
