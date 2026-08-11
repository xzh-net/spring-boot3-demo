package net.xzh.client.config;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Spring Security 6 + OAuth2 Client 安全配置.
 *
 * <p>核心能力：</p>
 * <ul>
 *   <li>所有请求需要认证（默认拦截 anyRequest）</li>
 *   <li>使用 OAuth2 Login（授权码模式）跳转授权服务器完成登录，自身无登录页</li>
 *   <li>登出时执行两步退出：① 调用 /oauth2/revoke 吊销 token；② 跳授权服务器 /logout 销毁 SSO 会话</li>
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
 * <p><b>两步退出关键点：</b>OAuth2 客户端完整退出需要两步组合，缺一不可：</p>
 * <ol>
 *   <li>调用授权服务器 {@code /oauth2/revoke} (RFC 7009) 吊销 access_token / refresh_token：
 *       让 Redis 中的 OAuth2Authorization 记录被删除，资源服务器 introspect 返回 401，
 *       管理后台「在线用户」列表对应会话减少。</li>
 *   <li>跳授权服务器 {@code /logout?redirect=...} 销毁 PORTAL HttpSession：
 *       否则下次浏览器访问 8083 触发 OAuth2 登录跳到 9000 的 /oauth2/authorize 时，
 *       9000 发现 session 中 PORTAL_SECURITY_CONTEXT 还在，直接发授权码不弹登录页，
 *       看起来像「退出后又自动登录回来了」。</li>
 * </ol>
 *
 * <p>不使用 Spring 自带的 {@code OidcClientInitiatedLogoutSuccessHandler} 的原因：
 * 它依赖 provider 元数据中的 {@code end_session_endpoint} 字段，而本系统的授权服务器
 * 手动配置了 {@code logout-uri}，该值不会被映射到 {@code end_session_endpoint}，
 * 导致 handler 回退到默认行为（跳到 {@code /}），触发 OAuth2 重新登录循环。</p>
 *
 * @author xzh
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    /** 授权服务器基础地址 (与 application.yml 中 provider 配置保持一致) */
    private static final String AUTH_SERVER_BASE = "http://localhost:9000";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   OAuth2AuthorizedClientRepository authorizedClientRepository) throws Exception {
        http
                // 静态资源与登出页放行
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/webjars/**", "/assets/**", "/logged-out", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                // OAuth2 登录：未认证请求会被重定向到授权服务器 /oauth2/authorize
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/oauth2/authorization/web-app-oidc"))
                // 两步退出：① /oauth2/revoke 吊销 token；② /logout 销毁 SSO 会话
                .logout(logout -> logout
                        .logoutSuccessHandler(new TwoStepLogoutSuccessHandler(
                                clientRegistrationRepository, authorizedClientRepository)));
        return http.build();
    }

    /**
     * 两步退出成功处理器.
     * <p>对应授权服务器管理后台首页文档中描述的「完整退出 = revoke token + logout session」流程，
     * 参考 oauth2-callback-web-app (8080) 的 handleLogout 实现。</p>
     *
     * <p>执行步骤：</p>
     * <ol>
     *   <li>从 {@link OAuth2AuthorizedClientRepository} 取出当前 access_token / refresh_token，
     *       并发调用 {@code /oauth2/revoke} 吊销 (RFC 7009)。吊销失败不阻断退出流程。</li>
     *   <li>构造 {@code http://localhost:9000/logout?redirect=http://localhost:8083/logged-out}
     *       并 302 跳转，授权服务器 Order(6) 链会执行 partialLogout 清 PORTAL_SECURITY_CONTEXT，
     *       并通过 revokeAuthorizationCodeGrantsForPrincipal 兜底撤销 authorization_code 型授权，
     *       最后回跳到 8083 的 /logged-out 静态页（已 permitAll，不会触发 OAuth2 登录）。</li>
     * </ol>
     */
    static final class TwoStepLogoutSuccessHandler implements LogoutSuccessHandler {

        private static final Logger log = LoggerFactory.getLogger(TwoStepLogoutSuccessHandler.class);

        private final ClientRegistrationRepository clientRegistrationRepository;
        private final OAuth2AuthorizedClientRepository authorizedClientRepository;

        /** 用于调用 /oauth2/revoke 的 HTTP 客户端 (Spring 6.1+ 内置) */
        private final RestClient restClient = RestClient.builder().build();

        TwoStepLogoutSuccessHandler(ClientRegistrationRepository clientRegistrationRepository,
                                   OAuth2AuthorizedClientRepository authorizedClientRepository) {
            this.clientRegistrationRepository = clientRegistrationRepository;
            this.authorizedClientRepository = authorizedClientRepository;
        }

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                    Authentication authentication) throws IOException {
            // 1. 吊销 OAuth2 token (RFC 7009 /oauth2/revoke)
            revokeTokens(request, authentication);

            // 2. 跳授权服务器 /logout 销毁 SSO 会话, 再回跳到本应用 /logged-out
            //    授权服务器 Order(6) 链读取 redirect 参数 (允许 localhost:8083)
            String clientLogoutUrl = buildBaseUrl(request) + "/logged-out";
            String serverLogoutUrl = AUTH_SERVER_BASE + "/logout?redirect="
                    + URLEncoder.encode(clientLogoutUrl, StandardCharsets.UTF_8);

            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", response.encodeRedirectURL(serverLogoutUrl));
            response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        }

        /**
         * 吊销当前已授权客户端的 access_token 和 refresh_token.
         * <p>吊销失败 (网络异常 / 服务端不可达 / token 不存在) 不阻断退出流程,
         * 授权服务器 /logout 中的 revokeAuthorizationCodeGrantsForPrincipal 会兜底撤销。</p>
         */
        private void revokeTokens(HttpServletRequest request, Authentication authentication) {
            if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
                return;
            }
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
            if (clientRegistration == null) {
                return;
            }
            OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                    registrationId, authentication, request);
            if (authorizedClient == null) {
                return;
            }

            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            if (accessToken != null) {
                revokeToken(clientRegistration, accessToken.getTokenValue(), "access_token");
            }
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            if (refreshToken != null) {
                revokeToken(clientRegistration, refreshToken.getTokenValue(), "refresh_token");
            }
        }

        /**
         * 调用 /oauth2/revoke 吊销单个 token (RFC 7009).
         * <p>请求格式：{@code POST /oauth2/revoke}
         * Header: {@code Authorization: Basic base64(client_id:client_secret)}
         * Body: {@code token=xxx&token_type_hint=access_token}</p>
         * <p>RFC 7009: 吊销成功一律返回 200 (即使 token 不存在也算成功)。</p>
         */
        private void revokeToken(ClientRegistration clientRegistration, String token, String tokenTypeHint) {
            if (token == null || token.isEmpty()) {
                return;
            }
            String auth = Base64.getEncoder().encodeToString(
                    (clientRegistration.getClientId() + ":" + clientRegistration.getClientSecret())
                            .getBytes(StandardCharsets.UTF_8));
            String body = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)
                    + "&token_type_hint=" + tokenTypeHint;
            try {
                restClient.post()
                        .uri(AUTH_SERVER_BASE + "/oauth2/revoke")
                        .header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .header("Authorization", "Basic " + auth)
                        .body(body)
                        .retrieve()
                        .toBodilessEntity();
                log.info("[logout] 已吊销 {} (HTTP 200)", tokenTypeHint);
            } catch (Exception e) {
                // 吊销失败不阻断退出流程, 授权服务器 /logout 会兜底撤销 authorization_code 型授权
                log.warn("[logout] 吊销 {} 失败 (不阻断退出): {}", tokenTypeHint, e.getMessage());
            }
        }

        /** 从当前请求构造 baseUrl, 如 {@code http://localhost:8083} */
        private static String buildBaseUrl(HttpServletRequest request) {
            String scheme = request.getScheme();
            String serverName = request.getServerName();
            int serverPort = request.getServerPort();
            String contextPath = request.getContextPath();
            return scheme + "://" + serverName + ":" + serverPort + contextPath;
        }
    }
}
