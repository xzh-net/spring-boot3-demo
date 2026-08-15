package net.xzh.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * 资源服务器安全配置.
 * <p>
 * 所有 /api/** 请求必须携带有效 Bearer Token, 由 {@link RbacAuthoritiesOpaqueTokenIntrospector}
 * 调用认证中心 /oauth2/introspect 完成 Opaque Token 校验, 并按业务 RBAC 注入 authorities.
 * <ul>
 *   <li>{@code /api/admin/**} — 【管理端能力】角色/权限管理, 仅允许 {@code ROLE_ADMIN}
 *       (管理台 admin-service, 见 §22.2 能力域);</li>
 *   <li>{@code /api/public/**} — 【portal 端能力】门户客户端目录, permitAll (当前 portal 专用/公开共用);</li>
 *   <li>{@code /api/contacts} — 【公开端能力】业务 API, 任意已认证用户;</li>
 *   <li>{@code /api/internal/**} — 【服务间内部能力】仅允许服务令牌
 *       (client_credentials 或 client_id ∈ service-client-ids 白名单, 注入 ROLE_SERVICE),
 *       且 client_id 必须在白名单内 (双保险, 供认证中心 M2M, 见 D6, 不属对外分类).</li>
 * </ul>
 * <p>控制器分包: {@code controller/admin|portal|client|internal} 与上述能力域一一对应。
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    private final AuthServerProperties authServerProperties;

    public ResourceServerConfig(AuthServerProperties authServerProperties) {
        this.authServerProperties = authServerProperties;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/internal/**").access(internalAccessManager(authServerProperties))
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.opaqueToken());
        return http.build();
    }

    /**
     * 内部接口访问决策: 请求令牌需同时满足「client_id 在服务白名单内」且「具备 ROLE_SERVICE」。
     * 白名单即 {@code authserver.service-client-ids} (默认 resource-server), 与 introspector
     * 注入 ROLE_SERVICE 的判据一致, 防止误注入的 ROLE_SERVICE 访问内部接口。
     */
    private static AuthorizationManager<RequestAuthorizationContext> internalAccessManager(AuthServerProperties props) {
        return (authentication, context) -> {
            Authentication auth = authentication.get();
            if (auth == null || !auth.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            boolean service = auth.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_SERVICE".equals(a.getAuthority()));
            if (!service) {
                return new AuthorizationDecision(false);
            }
            if (auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
                Object clientId = principal.getAttributes().get("client_id");
                if (clientId != null && props.getServiceClientIds().contains(clientId.toString())) {
                    return new AuthorizationDecision(true);
                }
            }
            return new AuthorizationDecision(false);
        };
    }
}