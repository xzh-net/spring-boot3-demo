package net.xzh.admin.security;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Token 有效性验证过滤器 (生产化三件套之二: 僵尸会话收口).
 * <p>
 * 定期检查 OAuth2 Access Token 是否仍然有效。如果 token 已被撤销 (认证中心强制下线/吊销),
 * 则清除本地会话并返回 401 —— 收掉"9000 已踢人但 BFF 本地会话还活着"的僵尸窗口。
 * 与 portal-bff 的同名过滤器同构 (仅注册 ID/配置键不同), 安全语义一致:
 * <ul>
 *   <li>缓存 30 秒避免每请求都打 introspection (僵尸窗口上界 = 30s + 下一请求);</li>
 *   <li>introspection 调用失败时降级放行 (网络抖动不误杀, 真失效由 9000 侧内省兜底);</li>
 *   <li>只对 OAuth2 登录态生效, 协议端点/登录/登出路径跳过。</li>
 * </ul>
 * token 来源: {@link OAuth2AuthorizedClientRepository} (本项目已改为 HttpSession 版,
 * 即与 session 同存 Redis — 校验用的与透传用的是同一份, 天然一致)。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenValidationFilter implements Filter {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** 认证中心 base url (单服务合并后即 9000) */
    @Value("${iam.auth-center-base-url}")
    private String authServerBaseUrl;

    @Value("${iam.introspection-uri:/oauth2/introspect}")
    private String introspectionUri;

    /** admin-app 客户端凭证 (client_secret_basic 用于 introspection) */
    @Value("${spring.security.oauth2.client.registration.admin-app.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.admin-app.client-secret}")
    private String clientSecret;

    private static final String REGISTRATION_ID = "admin-app";

    /** Token 验证结果缓存: token -> (active, expireTime) */
    private final Map<String, CacheEntry> tokenCache = new ConcurrentHashMap<>();

    /** 缓存有效期 (秒) */
    private static final long CACHE_TTL_SECONDS = 30;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

        if (shouldSkip(path)) {
            chain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }

        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token)) {
            chain.doFilter(request, response);
            return;
        }

        String accessToken = getAccessToken(httpRequest, oauth2Token);
        if (accessToken == null || accessToken.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        try {
            boolean tokenValid = validateTokenWithCache(accessToken);
            if (!tokenValid) {
                log.info("[TokenValidation] Token 已失效, 清除会话 (僵尸会话收口)");
                tokenCache.remove(accessToken);
                HttpSession session = httpRequest.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();

                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpResponse.setContentType("application/json;charset=UTF-8");
                httpResponse.getWriter().write("{\"authenticated\":false,\"error\":\"token_invalidated\",\"message\":\"登录已过期，请重新登录\"}");
                return;
            }
        } catch (Exception e) {
            // 验证异常降级放行: 网络抖动不误杀, token 真失效仍由 9000 侧内省兜底 (fail-closed 在资源侧)
            log.warn("[TokenValidation] Token 验证失败, 继续处理请求: {}", e.getMessage());
        }

        chain.doFilter(request, response);
    }

    /**
     * 判断是否应该跳过验证 (协议端点/登录/登出不校验 token).
     */
    private boolean shouldSkip(String path) {
        return path.startsWith("/oauth2/")
                || path.startsWith("/login")
                || path.startsWith("/logout")
                || path.startsWith("/actuator/")
                || path.equals("/error")
                || path.equals("/favicon.ico");
    }

    /**
     * 从 OAuth2 认证中获取 access_token (经 repository, 即 session 属性).
     */
    private String getAccessToken(HttpServletRequest request, OAuth2AuthenticationToken token) {
        try {
            var authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                    REGISTRATION_ID, token, request);
            if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
                return null;
            }
            return authorizedClient.getAccessToken().getTokenValue();
        } catch (Exception e) {
            log.warn("[TokenValidation] 获取 access_token 失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 带缓存的 token 验证 (30s TTL).
     */
    private boolean validateTokenWithCache(String token) throws Exception {
        CacheEntry cached = tokenCache.get(token);
        if (cached != null && cached.isValid()) {
            log.debug("[TokenValidation] 命中缓存, token={}... active={}",
                    token.substring(0, Math.min(20, token.length())), cached.active);
            return cached.active;
        }

        boolean active = validateToken(token);
        tokenCache.put(token, new CacheEntry(active, Instant.now().plusSeconds(CACHE_TTL_SECONDS)));

        log.debug("[TokenValidation] 更新缓存, token={}... active={}",
                token.substring(0, Math.min(20, token.length())), active);
        return active;
    }

    /**
     * 调认证中心 introspection 端点 (RFC 7662) 验证 token.
     */
    private boolean validateToken(String token) throws Exception {
        String url = authServerBaseUrl + introspectionUri;

        String credentials = clientId + ":" + clientSecret;
        String basicAuth = "Basic " + java.util.Base64.getEncoder().encodeToString(credentials.getBytes());

        String formBody = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)
                + "&token_type_hint=access_token";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(3))
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            String body = response.body();
            JsonNode node = objectMapper.readTree(body);
            boolean active = node.path("active").asBoolean(false);
            log.info("[TokenValidation] Introspection 结果: token={}... active={}",
                    token.substring(0, Math.min(20, token.length())), active);
            return active;
        }

        log.warn("[TokenValidation] Introspection 调用失败: HTTP {}", response.statusCode());
        return true; // 调用失败时假设 token 有效 (降级处理)
    }

    /**
     * 缓存条目.
     */
    private static class CacheEntry {
        final boolean active;
        final Instant expireTime;

        CacheEntry(boolean active, Instant expireTime) {
            this.active = active;
            this.expireTime = expireTime;
        }

        boolean isValid() {
            return Instant.now().isBefore(expireTime);
        }
    }
}
