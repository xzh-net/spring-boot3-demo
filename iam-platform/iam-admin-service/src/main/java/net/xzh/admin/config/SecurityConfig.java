package net.xzh.admin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * 管理后台服务安全配置.
 * <p>
 * 采用 OAuth2 Client (授权码模式) 登录认证中心。本服务不持有业务库,
 * 只作为 BFF 透传 /api/** 请求, 管理服务凭证 (ADMIN_SERVICE_TOKEN) 权限校验由对端 (认证中心/资源中心)
 * 在 introspection 时完成, 因此本服务只要求已登录。
 * <p>
 * 登录完成后经 {@link AdminOnlyLoginSuccessHandler} 独立准入: 非管理端 (无 ADMIN_SERVICE_TOKEN)
 * 直接拒绝并走认证中心 RP 登出清 SSO, 不建立后台会话。
 * <p>
 * 管理端登录成功重定向到 iam-admin-web (8001) 租户管理页; 登出走认证中心 RP-Initiated Logout。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AdminOnlyLoginSuccessHandler adminOnlyLoginSuccessHandler;

    public SecurityConfig(AdminOnlyLoginSuccessHandler adminOnlyLoginSuccessHandler) {
        this.adminOnlyLoginSuccessHandler = adminOnlyLoginSuccessHandler;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
                        .successHandler(adminOnlyLoginSuccessHandler))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/oauth2/authorization/admin-app")));
        return http.build();
    }
}