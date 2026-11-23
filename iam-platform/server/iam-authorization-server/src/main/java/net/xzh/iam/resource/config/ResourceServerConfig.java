package net.xzh.iam.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import jakarta.servlet.http.HttpServletResponse;

import net.xzh.iam.auth.security.token.RedisOpaqueTokenIntrospector;

/**
 * 统一 API 资源服务器安全链 (Order(3)).
 * <p>
 * 只接管业务端点三前缀 {@code /admin/** | /biz/** | /permitall/**}
 * (按 controller 分包命名: admin=管理端 / portal=业务(门户+三方) / permitall=免权限),
 * 其余路径由协议链 (Order(1)) 与设备验证链 (Order(2)) 处理,
 * 准入分三档:
 * <ul>
 *   <li>{@code /permitall/**} — 链层 permitAll, 免令牌不经裁决;</li>
 *   <li>表内端点 (启动扫描播种) — 由
 *       {@link EndpointAdmissionManager} 按 policy_type + 权限码组合 (ALL/ANY) 裁决
 *       (客户端维度隔离由令牌双维交集承担);</li>
 *   <li>表外其余三前缀端点 — 一律拒绝 403 (fail-closed, A-P0-4 改判; 启动漂移告警提示补行);</li>
 * </ul>
 * Bearer Token 由 {@link RedisOpaqueTokenIntrospector} 同进程本地内省
 * (Redis 查授权记录, 无 HTTP 自回环), 并按业务 RBAC ∩ 客户端 scope 双维交集注入 authorities
 * (A-P2-4: 原双层 RbacAuthorities 包装已并入单层)。
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(3)
public class ResourceServerConfig {

    private final EndpointAdmissionManager endpointAdmissionManager;
    private final RedisOpaqueTokenIntrospector opaqueTokenIntrospector;

    public ResourceServerConfig(EndpointAdmissionManager endpointAdmissionManager,
                                RedisOpaqueTokenIntrospector opaqueTokenIntrospector) {
        this.endpointAdmissionManager = endpointAdmissionManager;
        this.opaqueTokenIntrospector = opaqueTokenIntrospector;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/admin/**", "/biz/**", "/permitall/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/permitall/**").permitAll()
                        .anyRequest().access(endpointAdmissionManager))
                .oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(
                        token -> token.introspector(opaqueTokenIntrospector)))
                // 认证/授权失败分别以 JSON 401 / 403 返回,
                // 避免与协议链的登录页跳转冲突
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
                        }));
        return http.build();
    }
}
