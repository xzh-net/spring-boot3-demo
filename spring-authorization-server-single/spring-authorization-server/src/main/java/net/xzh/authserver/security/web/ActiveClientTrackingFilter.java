package net.xzh.authserver.security.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;

/**
 * 跟踪当前会话最后活跃的客户端 ID (registeredClientId).
 * <p>
 * 支持两种追踪场景：
 * <ol>
 *   <li><b>Token 端点 (/oauth2/token)</b>：客户端用 authorization_code / refresh_token /
 *       password 等 grant 换取 token 时，从请求参数或 Basic Auth header 中提取 client_id。
 *       仅在响应成功 (HTTP 200) 时更新，避免失败的 token 请求污染 Session。</li>
 *   <li><b>资源请求 (携带 Bearer Token)</b>：客户端访问 /api/** 或 /userinfo 时，
 *       解析 Authorization 头中的 Bearer Token，通过 RedisOAuth2AuthorizationService
 *       反查对应的 OAuth2Authorization，提取 registeredClientId。</li>
 * </ol>
 * </p>
 *
 * <p>
 * 目的：实现多客户端会话隔离。当用户点击退出 (调用 /logout) 时，服务端
 * 可从 Session 中读取此值，精确撤销该客户端的 OAuth2Authorization，
 * 而不影响同一用户在其他客户端 (如 8082 mobile-app) 上的登录态。
 * </p>
 *
 * <p>
 * 注意：对于 /logout 本身 (不带 Bearer Token，也不是 /oauth2/token)，本 Filter 不会更新
 * ACTIVE_CLIENT_ID，从而保留最后一次操作时的客户端 ID，供退出逻辑使用。
 * </p>
 */
@Slf4j
public final class ActiveClientTrackingFilter extends OncePerRequestFilter {

    /**
     * 用于查询 Token 对应的授权记录，从而获取 registeredClientId.
     */
    private final RedisOAuth2AuthorizationService authorizationService;

    /**
     * 存储当前活跃客户端 ID 的 Session 属性键.
     */
    public static final String ACTIVE_CLIENT_ID_ATTR = "ACTIVE_CLIENT_ID";

    /**
     * Token 端点路径，用于识别需要从请求参数提取 client_id 的场景.
     */
    private static final String TOKEN_ENDPOINT = "/oauth2/token";

    public ActiveClientTrackingFilter(RedisOAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 1. 先执行后续过滤链，让 token 端点处理 / SecurityContext 加载完成
        filterChain.doFilter(request, response);

        // 2. 请求处理完成后，尝试追踪活跃客户端
        //    对于 /logout 请求，两种场景都不匹配，不会更新 ACTIVE_CLIENT_ID,
        //    从而保留用户在点击退出按钮前的最后活跃客户端 ID
        String clientId = resolveClientId(request, response);
        if (clientId == null) {
            return;
        }
        // 【关键】响应已提交时不能创建 session (Spring Session 限制)
        // 这在 STATELESS 资源服务器链 (/api/**) 上会发生: 控制器返回响应后 filter 才执行到这里
        // 此时若强制 request.getSession(true) 会抛 IllegalStateException, 导致 8080 客户端请求挂起
        if (response.isCommitted()) {
            log.debug("[ActiveClientTracking] 响应已提交, 跳过 session 写入 clientId={}", clientId);
            return;
        }
        try {
            // getSession(false) 不强制创建: STATELESS 链上没有 session 时跳过, 避免破坏无状态语义
            HttpSession session = request.getSession(false);
            if (session == null) {
                log.debug("[ActiveClientTracking] 无可用 session, 跳过 clientId={} (STATELESS 链)", clientId);
                return;
            }
            String existingId = (String) session.getAttribute(ACTIVE_CLIENT_ID_ATTR);
            if (!clientId.equals(existingId)) {
                session.setAttribute(ACTIVE_CLIENT_ID_ATTR, clientId);
                log.debug("[ActiveClientTracking] 记录活跃客户端 clientId={}, sessionId={}", clientId, session.getId());
            }
        } catch (IllegalStateException e) {
            // 兜底: 即使 isCommitted 检查通过, 也可能因并发提交失败
            log.debug("[ActiveClientTracking] 写入 session 失败 (可能响应已提交): {}", e.getMessage());
        }
    }

    /**
     * 解析当前请求对应的客户端 ID，优先处理 token 端点，其次处理 Bearer Token 请求.
     *
     * @param request  当前 HTTP 请求
     * @param response 当前 HTTP 响应 (用于判断 token 端点是否成功)
     * @return registeredClientId，如果无法确定则返回 null
     */
    private String resolveClientId(HttpServletRequest request, HttpServletResponse response) {
        // 场景 1: /oauth2/token 请求 (authorization_code / refresh_token / password / client_credentials)
        // 从请求参数或 Basic Auth header 提取 client_id，仅在响应成功 (200) 时更新
        String clientId = resolveClientIdFromTokenEndpoint(request, response);
        if (clientId != null) {
            return clientId;
        }

        // 场景 2: 携带 Bearer Token 的资源请求 (/api/**, /userinfo)
        // 从 Authorization header 解析 token，反查 Redis 获取 registeredClientId
        return resolveClientIdFromBearerToken(request);
    }

    /**
     * 从 /oauth2/token 请求中提取 client_id.
     * <p>
     * 支持两种客户端认证方式：
     * <ul>
     *   <li>Public Client (如 mobile-app): 请求参数 client_id=xxx</li>
     *   <li>Confidential Client (如 web-app): Authorization: Basic base64(client_id:client_secret)</li>
     * </ul>
     * 仅在 HTTP 200 响应时更新，避免 token 请求失败 (如 invalid_grant) 污染 Session。
     * </p>
     *
     * @param request  当前 HTTP 请求
     * @param response 当前 HTTP 响应
     * @return client_id，如果不是 token 端点请求或响应非 200 则返回 null
     */
    private String resolveClientIdFromTokenEndpoint(HttpServletRequest request, HttpServletResponse response) {
        if (!TOKEN_ENDPOINT.equals(request.getRequestURI())) {
            return null;
        }
        // token 请求失败 (如 invalid_grant / invalid_client) 时不更新 ACTIVE_CLIENT_ID
        if (response.getStatus() != HttpServletResponse.SC_OK) {
            return null;
        }

        // 1. 优先从请求参数获取 (public client 如 mobile-app)
        String clientId = request.getParameter("client_id");
        if (clientId != null && !clientId.isBlank()) {
            return clientId;
        }

        // 2. 从 Basic Auth header 获取 (confidential client 如 web-app)
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            try {
                String decoded = new String(
                        Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                if (colon > 0) {
                    return decoded.substring(0, colon);
                }
            } catch (IllegalArgumentException e) {
                log.debug("[ActiveClientTracking] Basic Auth header 解码失败: {}", e.getMessage());
            }
        }

        return null;
    }

    /**
     * 从请求头 Authorization 解析 Bearer Token，并查询对应的 registeredClientId.
     *
     * @param request 当前 HTTP 请求
     * @return registeredClientId，如果请求没有有效 Bearer Token 或查询失败则返回 null
     */
    private String resolveClientIdFromBearerToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || authHeader.isBlank()) {
            return null;
        }
        String prefix = "Bearer ";
        if (!authHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return null;
        }
        String tokenValue = authHeader.substring(prefix.length()).trim();
        if (tokenValue.isEmpty()) {
            return null;
        }

        try {
            OAuth2Authorization auth = authorizationService.findByToken(tokenValue, OAuth2TokenType.ACCESS_TOKEN);
            if (auth != null && auth.getRegisteredClientId() != null) {
                return auth.getRegisteredClientId();
            }
        } catch (Exception e) {
            log.warn("[ActiveClientTracking] 查询 Token 对应的授权记录失败: {}", e.getMessage());
        }
        return null;
    }
}
