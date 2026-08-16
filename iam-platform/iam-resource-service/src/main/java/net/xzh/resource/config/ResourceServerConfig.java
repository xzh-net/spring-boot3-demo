package net.xzh.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * 资源服务器安全配置.
 * <p>
 * 所有 /api/** 请求必须携带有效 Bearer Token, 由 {@link RbacAuthoritiesOpaqueTokenIntrospector}
 * 调用认证中心 /oauth2/introspect 完成 Opaque Token 校验, 并按业务 RBAC 注入 authorities。
 * <p>
 * 接口准入由 {@link EndpointAdmissionManager} 表驱动 (iam_endpoint_policy):
 * 启动扫描播种每个端点的默认规则并按域分类, 管理端可覆盖; 未登记路径默认拒绝。能力域划分:
 * <ul>
 *   <li>{@code controller/admin}      — 管理端能力, {@code ADMIN_SERVICE_TOKEN} 管理服务凭证;</li>
 *   <li>{@code controller/portal}     — portal 端能力, {@code PORTAL_SERVICE_TOKEN} 门户服务凭证 + portal 客户端白名单;</li>
 *   <li>{@code controller/capability} — 开放能力 (/api/capability/**), 任意凭证 + 能力订阅校验;</li>
 *   <li>{@code controller/internal}   — 服务间内部能力, {@code PORTAL_SERVICE_TOKEN} 门户服务凭证 + client_id 白名单双保险;</li>
 *   <li>{@code controller/permitall}  — 放行域 (/api/permitall/**), 无认证要求.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    private final EndpointAdmissionManager endpointAdmissionManager;

    public ResourceServerConfig(EndpointAdmissionManager endpointAdmissionManager) {
        this.endpointAdmissionManager = endpointAdmissionManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/error").permitAll()
                        .anyRequest().access(endpointAdmissionManager))
                .oauth2ResourceServer(oauth2 -> oauth2.opaqueToken());
        return http.build();
    }
}