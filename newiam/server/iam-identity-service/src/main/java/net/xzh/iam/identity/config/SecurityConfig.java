package net.xzh.iam.identity.config;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 身份管理面安全配置 (OAuth2 资源服务器, STATELESS).
 * <p>
 * 管理面准入与旧认证中心 Order(2) 管理链语义一致:
 * <ul>
 *   <li>令牌须为管理台用户令牌 (opaque introspection 校验, 认证中心签发);</li>
 *   <li>令牌主体须具备 {@code ADMIN_SERVICE_TOKEN} (管理服务凭证, 由 ADMIN 业务角色派生);</li>
 *   <li>令牌 client_id 须在 {@code identity.admin-client-ids} 白名单 (默认 [admin-app])。</li>
 * </ul>
 * 认证/授权失败分别以 JSON 401 / 403 返回 (与下游内部 API 错误风格一致)。
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    /** 管理服务凭证类别标识 (用户令牌持有者具备管理端业务角色时派生) */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    private final IdentityProperties properties;

    @Bean
    public SecurityFilterChain managementApiSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/**")
                .authorizeHttpRequests(auth -> auth
                        .anyRequest()
                        .access(managementAccessManager(properties.getAdminClientIds())))
                .oauth2ResourceServer(rs -> rs.opaqueToken(Customizer.withDefaults()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
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
                        }))
                .csrf(csrf -> csrf.disable());
        return http.build();
    }

    /**
     * 管理面访问决策: ADMIN_SERVICE_TOKEN 准入 + client_id 白名单。
     */
    private static AuthorizationManager<RequestAuthorizationContext> managementAccessManager(
            Set<String> adminClientIds) {
        return (authenticationSupplier, context) -> {
            Authentication auth = authenticationSupplier.get();
            if (auth == null || !auth.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            boolean hasAdminAuthority = auth.getAuthorities().stream()
                    .anyMatch(a -> ADMIN_SERVICE_TOKEN.equals(a.getAuthority()));
            if (!hasAdminAuthority) {
                return new AuthorizationDecision(false);
            }
            if (auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
                Object clientId = principal.getAttributes().get("client_id");
                if (clientId != null && adminClientIds.contains(clientId.toString())) {
                    return new AuthorizationDecision(true);
                }
            }
            return new AuthorizationDecision(false);
        };
    }
}
