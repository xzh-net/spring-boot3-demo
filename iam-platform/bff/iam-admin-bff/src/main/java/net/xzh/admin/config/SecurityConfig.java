package net.xzh.admin.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * 管理后台服务安全配置.
 * <p>
 * 采用 OAuth2 Client (授权码模式) 登录认证中心。本服务不持有业务库,
 * 只作为 BFF 透传 /api/** 请求, 权限校验由认证中心在令牌自省时完成 (双维交集), 因此本服务只要求已登录。
 * <p>
 * <b>PKCE (RFC 7636)</b>：`admin-app` 已设 {@code requireProofKey=true}，本服务必须在授权请求中携带
 * {@code code_challenge=S256(sha256(code_verifier))}，并在换令牌时回传 {@code code_verifier}，
 * 否则认证中心会直接拒绝授权请求。实现与 iam-portal-bff 一致（client_secret_basic 的
 * confidential 客户端同样受益于该「独立第二道防线」：secret 泄露仍无法兑换令牌）。
 * <p>
 * 登录完成后经 {@link AdminOnlyLoginSuccessHandler} 独立准入: 非管理端令牌直接拒绝并走
 * 认证中心 RP 登出清 SSO, 不建立后台会话。登出走 RP-Initiated Logout。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AdminOnlyLoginSuccessHandler adminOnlyLoginSuccessHandler;

    public SecurityConfig(AdminOnlyLoginSuccessHandler adminOnlyLoginSuccessHandler) {
        this.adminOnlyLoginSuccessHandler = adminOnlyLoginSuccessHandler;
    }

    /** PKCE code_verifier 生成器: 32 字节随机数, Base64URL 编码 = 43 字符 (RFC 7636 要求 43~128) */
    private static final StringKeyGenerator CODE_VERIFIER_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

    /**
     * 构造带 PKCE 的 OAuth2 授权请求 (RFC 7636).
     * <ol>
     *   <li>生成一次性 code_verifier</li>
     *   <li>计算 code_challenge = base64url(sha256(code_verifier))</li>
     *   <li>challenge 随授权请求发往认证服务器；verifier 存入 OAuth2AuthorizationRequest
     *       的 additionalParameters（自动落到 HttpSession），回调换令牌时取出</li>
     * </ol>
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
            builder.additionalParameters(params ->
                    params.put(PkceParameterNames.CODE_VERIFIER, codeVerifier));
            builder.parameters(params -> {
                params.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge);
                params.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
            });
        });
        return delegate;
    }

    /**
     * 构造带 PKCE code_verifier 的令牌请求.
     * <p>Spring 默认的 OAuth2AuthorizationCodeGrantRequestEntityConverter 只带 client_secret；
     * 这里扩展为从 session 中保存的授权请求 additionalParameters 取出 code_verifier 拼入表单。
     */
    @Bean
    public DefaultAuthorizationCodeTokenResponseClient pkceTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        OAuth2AuthorizationCodeGrantRequestEntityConverter delegate =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        delegate.addParametersConverter(grantRequest -> {
            MultiValueMap<String, String> mv = new LinkedMultiValueMap<>();
            Object codeVerifier = grantRequest.getAuthorizationExchange()
                    .getAuthorizationRequest()
                    .getAdditionalParameters()
                    .get(PkceParameterNames.CODE_VERIFIER);
            if (codeVerifier != null) {
                mv.add(PkceParameterNames.CODE_VERIFIER, codeVerifier.toString());
            }
            return mv;
        });
        client.setRequestEntityConverter(delegate);
        return client;
    }

    /** RFC 7636 §4.6: code_challenge = BASE64URL( SHA256( ASCII(code_verifier) ) ) */
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

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            OAuth2AuthorizationRequestResolver pkceAuthorizationRequestResolver,
                                            DefaultAuthorizationCodeTokenResponseClient pkceTokenResponseClient) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                // 禁用默认 LogoutFilter: 它会把 GET /logout 直接跳转到 /login?logout,
                // 拦截掉本服务的 RP-Initiated Logout 处理器 (AuthLogoutController),
                // 导致退出不经过认证中心端会话注销. 登出由 AuthLogoutController 全权处理。
                .logout(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        // OAuth2 回调端点放行
                        .requestMatchers("/error", "/login", "/login/**", "/logout", "/oauth2/**").permitAll()
                        // 其余 (含 /api/**) 均需登录
                        .anyRequest().authenticated())
                .oauth2Login(login -> login
                        // PKCE: 授权请求带 code_challenge
                        .authorizationEndpoint(ae -> ae.authorizationRequestResolver(pkceAuthorizationRequestResolver))
                        // PKCE: 换令牌带 code_verifier
                        .tokenEndpoint(te -> te.accessTokenResponseClient(pkceTokenResponseClient))
                        .successHandler(adminOnlyLoginSuccessHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/admin-app")));
        return http.build();
    }
}
