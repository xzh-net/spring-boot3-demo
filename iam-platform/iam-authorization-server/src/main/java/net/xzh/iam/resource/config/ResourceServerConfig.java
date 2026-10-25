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

/**
 * 统一 API 资源服务器安全链 (阶段 3 三链合一: Order(3)).
 * <p>
 * 只接管 {@code /api/**}, 其余路径由协议链 (Order(1)) 与设备验证链 (Order(2)) 处理,
 * 不再有兜底 catch-all 链。准入分三档:
 * <ul>
 *   <li>{@code /api/permitall/**} — 链层 permitAll, 免令牌不经裁决;</li>
 *   <li>表内三域 {@code controller/admin | portal | third} — 启动扫描播种, 由
 *       {@link EndpointAdmissionManager} 按 {@code required_authority} 裁决
 *       (粗档常量或权限码), admin/portal 叠加客户端白名单;</li>
 *   <li>表外其余 {@code /api/**} — 走认证档, 持有效 Bearer Token 即放行。</li>
 * </ul>
 * Bearer Token 由 {@link RbacAuthoritiesOpaqueTokenIntrospector} 同进程本地内省
 * (Redis 查授权记录, 无 HTTP 自回环), 并按业务 RBAC 注入 authorities。
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(3)
public class ResourceServerConfig {

    private final EndpointAdmissionManager endpointAdmissionManager;
    private final RbacAuthoritiesOpaqueTokenIntrospector rbacAuthoritiesOpaqueTokenIntrospector;

    public ResourceServerConfig(EndpointAdmissionManager endpointAdmissionManager,
                                RbacAuthoritiesOpaqueTokenIntrospector rbacAuthoritiesOpaqueTokenIntrospector) {
        this.endpointAdmissionManager = endpointAdmissionManager;
        this.rbacAuthoritiesOpaqueTokenIntrospector = rbacAuthoritiesOpaqueTokenIntrospector;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/permitall/**").permitAll()
                        .anyRequest().access(endpointAdmissionManager))
                .oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(
                        token -> token.introspector(rbacAuthoritiesOpaqueTokenIntrospector)))
                // 认证/授权失败分别以 JSON 401 / 403 返回 (原 adminApi 链语义),
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
