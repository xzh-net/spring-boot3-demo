package net.xzh.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Spring Security 6 + OAuth2 Client 安全配置.
 *
 * <p>核心能力：</p>
 * <ul>
 *   <li>所有请求需要认证（默认拦截 anyRequest）</li>
 *   <li>使用 OAuth2 Login（授权码模式）跳转授权服务器完成登录，自身无登录页</li>
 *   <li>登出时通过 OIDC RP-Initiated Logout 协议通知授权服务器一起登出</li>
 * </ul>
 *
 * <p>对应 application.yml 中 registrationId = "web-app-oidc"。</p>
 *
 * <p><b>SSO 会话隔离关键点：</b>本应用（8083）与授权服务器（9000）同在 localhost，
 * 若两者都使用默认的 JSESSIONID cookie，浏览器在 8083 → 9000 → 8083 的跳转过程中
 * 9000 的 JSESSIONID 会覆盖 8083 的，导致 8083 的 HttpSession 丢失，
 * {@code OAuth2LoginAuthenticationFilter} 处理 /login/oauth2/code 时找不到之前存的
 * {@code OAuth2AuthorizationRequest}，抛出 state mismatch，SSO 失败。</p>
 *
 * <p>解决方案：在 application.yml 中通过 {@code server.servlet.session.cookie.name=CLIENT_SESSION}
 * 给本应用设置独立的 session cookie 名称，避免与 9000 的 JSESSIONID 冲突。
 * 8083 的 {@code OAuth2AuthorizationRequest} 存在 HttpSession 中，
 * 只要 CLIENT_SESSION cookie 不被覆盖，回跳时即可正常取回。</p>
 *
 * @author xzh
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository) throws Exception {
        http
                // 静态资源与登出页放行
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/webjars/**", "/assets/**", "/logged-out", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                // OAuth2 登录：未认证请求会被重定向到授权服务器 /oauth2/authorize
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/oauth2/authorization/web-app-oidc"))
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
        return http.build();
    }

    /**
     * OIDC RP-Initiated Logout：客户端登出时携带 id_token_hint 回到授权服务器 end_session_endpoint，
     * 让授权服务器一并清除 SSO 会话。登出后回到本应用的 /logged-out 页面。
     */
    private LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler handler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}/logged-out");
        return handler;
    }
}
