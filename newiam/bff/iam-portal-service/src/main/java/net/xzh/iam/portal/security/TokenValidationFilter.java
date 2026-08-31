package net.xzh.iam.portal.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;

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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Token 有效性验证过滤器.
 * <p>
 * 定期检查 OAuth2 Access Token 是否仍然有效。
 * 如果 token 已被撤销（强制下线），则清除本地会话并返回 401。
 * <p>
 * 使用缓存避免每次请求都调用 introspection 端点，缓存有效期 30 秒。
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

    @Value("${auth-server.base-url}")
    private String authServerBaseUrl;

    @Value("${auth-server.introspection-uri:/oauth2/introspect}")
    private String introspectionUri;

    @Value("${spring.security.oauth2.client.registration.portal-app-oidc.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.portal-app-oidc.client-secret}")
    private String clientSecret;

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

        // 跳过静态资源和 OAuth2 相关路径
        if (shouldSkip(path)) {
            chain.doFilter(request, response);
            return;
        }

        // 获取当前认证信息
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            chain.doFilter(request, response);
            return;
        }

        // 只有 OAuth2 认证需要验证
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token)) {
            chain.doFilter(request, response);
            return;
        }

        // 获取 access_token
        String accessToken = getAccessToken(httpRequest, oauth2Token);
        if (accessToken == null || accessToken.isBlank()) {
            chain.doFilter(request, response);
            return;
        }

        // 验证 token 有效性 (带缓存)
        try {
            boolean tokenValid = validateTokenWithCache(accessToken);
            if (!tokenValid) {
                log.info("[TokenValidation] Token 已失效，清除会话");
                // 清除缓存
                tokenCache.remove(accessToken);
                HttpSession session = httpRequest.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
                SecurityContextHolder.clearContext();

                // 返回 401
                httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                httpResponse.setContentType("application/json;charset=UTF-8");
                httpResponse.getWriter().write("{\"authenticated\":false,\"error\":\"token_invalidated\",\"message\":\"登录已过期，请重新登录\"}");
                return;
            }
        } catch (Exception e) {
            log.warn("[TokenValidation] Token 验证失败，继续处理请求: {}", e.getMessage());
        }

        chain.doFilter(request, response);
    }

    /**
     * 判断是否应该跳过验证.
     */
    private boolean shouldSkip(String path) {
        return path.startsWith("/oauth2/")
                || path.startsWith("/login")
                || path.startsWith("/logout")
                || path.startsWith("/actuator/")
                || path.equals("/error")
                || path.equals("/favicon.ico")
                || path.endsWith(".css")
                || path.endsWith(".js")
                || path.endsWith(".ico")
                || path.endsWith(".svg")
                || path.endsWith(".png");
    }

    /**
     * 从 OAuth2 认证中获取 access_token.
     */
    private String getAccessToken(HttpServletRequest request, OAuth2AuthenticationToken token) {
        try {
            String registrationId = "portal-app-oidc";
            var authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                    registrationId, token, request);
            if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
                return null;
            }
            return authorizedClient.getAccessToken().getTokenValue();
        } catch (Exception e) {
            log.warn("获取 access_token 失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 带缓存的 token 验证.
     * <p>
     * 如果缓存中有有效结果，直接返回；否则调用 introspection 端点。
     */
    private boolean validateTokenWithCache(String token) throws Exception {
        // 检查缓存
        CacheEntry cached = tokenCache.get(token);
        if (cached != null && cached.isValid()) {
            log.debug("[TokenValidation] 命中缓存, token={}... active={}",
                    token.substring(0, Math.min(20, token.length())), cached.active);
            return cached.active;
        }

        // 调用 introspection
        boolean active = validateToken(token);

        // 更新缓存
        tokenCache.put(token, new CacheEntry(active, Instant.now().plusSeconds(CACHE_TTL_SECONDS)));

        log.debug("[TokenValidation] 更新缓存, token={}... active={}",
                token.substring(0, Math.min(20, token.length())), active);

        return active;
    }

    /**
     * 调用认证中心 introspection 端点验证 token.
     */
    private boolean validateToken(String token) throws Exception {
        String url = authServerBaseUrl + introspectionUri;

        // 构建 Basic Auth header
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
        return true; // 调用失败时假设 token 有效（降级处理）
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
