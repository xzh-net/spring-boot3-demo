package net.xzh.iam.open.config;

import java.util.Map;
import java.util.Collection;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.open.service.CapabilityService;

/**
 * 开放平台安全配置 (OAuth2 资源服务器, STATELESS).
 * <p>
 * 准入模型 (自包含, 不复用权限中心 endpoint_policy——能力目录表
 * iam_api_capability 本身就是开放平台的 API 准入登记表):
 * <ul>
 *   <li>{@code /api/admin/**} (能力/订阅管理域): ADMIN_SERVICE_TOKEN 准入
 *       (管理台用户令牌具备 ADMIN 角色, 或管理 M2M 服务令牌);</li>
 *   <li>{@code /api/capability/**} (能力开放域): 认证通过 + 能力登记裁决
 *       ({@link CapabilityService#admit}: 路由匹配 → scope → 订阅有效性), 未登记默认拒绝;</li>
 *   <li>其余路径: 一律拒绝。</li>
 * </ul>
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class OpenSecurityConfig {

    /** 管理服务凭证类别标识 */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    private final CapabilityService capabilityService;

    @Bean
    public SecurityFilterChain openSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/admin/**").access(adminDomainAccess())
                        .requestMatchers("/api/capability/**").access(capabilityDomainAccess())
                        .anyRequest().denyAll())
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

    /** 管理域: ADMIN_SERVICE_TOKEN 准入 */
    private static AuthorizationManager<RequestAuthorizationContext> adminDomainAccess() {
        return (authSupplier, context) -> {
            Authentication auth = authSupplier.get();
            boolean allowed = auth != null && auth.isAuthenticated() && auth.getAuthorities().stream()
                    .anyMatch(a -> ADMIN_SERVICE_TOKEN.equals(a.getAuthority()));
            return new AuthorizationDecision(allowed);
        };
    }

    /** 能力开放域: 认证通过 + 能力登记/订阅裁决 (委托能力服务) */
    private AuthorizationManager<RequestAuthorizationContext> capabilityDomainAccess() {
        return (authSupplier, context) -> {
            Authentication auth = authSupplier.get();
            if (auth == null || !auth.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            var admission = capabilityService.admit(context.getRequest().getMethod(),
                    context.getRequest().getRequestURI(), attributesOf(auth), scopesOf(auth));
            log.debug("[Open] 能力准入 {} {} -> {}", context.getRequest().getMethod(),
                    context.getRequest().getRequestURI(), admission);
            return new AuthorizationDecision(admission == CapabilityService.Admission.ALLOWED);
        };
    }

    private static Map<String, Object> attributesOf(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof OAuth2AuthenticatedPrincipal principal) {
            return principal.getAttributes();
        }
        return Map.of();
    }

    private static Collection<String> scopesOf(Authentication auth) {
        List<String> scopes = new java.util.ArrayList<>();
        if (auth != null) {
            for (GrantedAuthority authority : auth.getAuthorities()) {
                if (authority.getAuthority().startsWith("SCOPE_")) {
                    scopes.add(authority.getAuthority().substring("SCOPE_".length()));
                }
            }
        }
        return scopes;
    }

}
