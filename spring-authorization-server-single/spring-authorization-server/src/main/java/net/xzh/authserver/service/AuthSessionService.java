package net.xzh.authserver.service;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.vo.SessionVO;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthSessionService {

    private final RedisOAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final SessionRegistry sessionRegistry;
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private static <T extends OAuth2Token> T unwrap(
            OAuth2Authorization.Token<T> wrapper) {
        return wrapper != null ? wrapper.getToken() : null;
    }

    /**
     * 在线用户列表 (按用户名聚合)。
     */
    public List<Map<String, Object>> listOnlineUsers() {
        Set<String> principals = authorizationService.findAllOnlinePrincipals();
        List<Map<String, Object>> result = new ArrayList<>();
        for (String principal : principals) {
            List<OAuth2Authorization> sessions = authorizationService.findByPrincipal(principal);
            // 跳过无有效会话的 principal (如设备码流程中 client_id 残留的旧索引)
            if (sessions.isEmpty()) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("principalName", principal);
            row.put("sessionCount", sessions.size());

            // 首次登录: 最早的 access_token 签发时间 (用户首次认证的时刻)
            row.put("loginTime", sessions.stream()
                    .map(a -> unwrap(a.getAccessToken()))
                    .filter(t -> t != null && t.getIssuedAt() != null)
                    .map(t -> FMT.format(t.getIssuedAt()))
                    .min(String::compareTo).orElse("-"));

            // 最近登录: 最新的 access_token 签发时间 (最近一次登录或刷新令牌的时刻, 非最后活跃时间)
            row.put("lastAccessTime", sessions.stream()
                    .map(a -> unwrap(a.getAccessToken()))
                    .filter(t -> t != null && t.getIssuedAt() != null)
                    .map(t -> FMT.format(t.getIssuedAt()))
                    .max(String::compareTo).orElse("-"));

            // 客户端列表
            row.put("clients", sessions.stream()
                    .map(this::resolveClientName)
                    .filter(c -> c != null && !c.isEmpty())
                    .distinct()
                    .reduce((a, b) -> a + ", " + b)
                    .orElse("-"));

            // 授权类型列表 (返回原始 grant type 值数组, 前端用彩色标签渲染)
            row.put("grantTypes", sessions.stream()
                    .map(a -> a.getAuthorizationGrantType().getValue())
                    .distinct()
                    .toList());

            result.add(row);
        }
        return result;
    }

    /**
     * 指定用户的所有会话明细。
     */
    public List<SessionVO> listSessionsByPrincipal(String principalName) {
        return authorizationService.findByPrincipal(principalName).stream()
                .map(this::toSessionVO)
                .toList();
    }

    /**
     * 所有设备码会话 (grantType=device_code)。
     */
    public List<SessionVO> listDeviceSessions() {
        List<SessionVO> result = new ArrayList<>();
        Set<String> principals = authorizationService.findAllOnlinePrincipals();
        for (String principal : principals) {
            for (OAuth2Authorization auth : authorizationService.findByPrincipal(principal)) {
                if ("urn:ietf:params:oauth:grant-type:device_code".equals(
                        auth.getAuthorizationGrantType().getValue())) {
                    result.add(toSessionVO(auth));
                }
            }
        }
        return result;
    }

    /**
     * 下线指定用户所有会话: 删除 OAuth2 授权记录 + 终止 HttpSession.
     * 终止 HttpSession 后, 客户端重新走 /oauth2/authorize 时不会免登录直接拿 code,
     * 而是被强制跳到登录页重新输入密码.
     */
    public int revokeUserAll(String principalName) {
        invalidateHttpSessions(principalName);
        return authorizationService.revokeAllByPrincipal(principalName);
    }

    /**
     * 下线单个会话 (仅撤销 OAuth2Authorization 令牌, 不终止 HttpSession).
     * <p>
     * 踢单个设备/令牌时, 只删除 Redis 中的授权记录使 token 失效,
     * 不影响用户的门户登录会话 (HttpSession). 令牌和会话是独立的概念.
     * 如需同时终止门户会话, 使用 {@link #revokeUserAll(String)}.
     */
    public boolean revokeSession(String authorizationId) {
        return authorizationService.revokeById(authorizationId);
    }

    /**
     * 下线指定用户在指定客户端上的所有会话 (取消授权时调用)。
     */
    public int revokeByPrincipalAndClient(String principalName, String registeredClientId) {
        int count = 0;
        for (OAuth2Authorization auth : authorizationService.findByPrincipal(principalName)) {
            if (registeredClientId.equals(auth.getRegisteredClientId())) {
                authorizationService.revoke(auth);
                count++;
            }
        }
        return count;
    }

    /**
     * 通过 SessionRegistry 终止用户的所有 HttpSession.
     * expireNow() 标记 session 为过期, 下次请求时 ConcurrentSessionFilter 检测到后
     * 会销毁 session 并重定向到登录页, 强制用户重新认证.
     */
    private void invalidateHttpSessions(String principalName) {
        try {
            for (Object principal : sessionRegistry.getAllPrincipals()) {
                if (principal instanceof User user && principalName.equals(user.getUsername())) {
                    for (SessionInformation session : sessionRegistry.getAllSessions(user, true)) {
                        session.expireNow();
                        log.info("已终止 HttpSession sessionId={}, principal={}", session.getSessionId(), principalName);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("终止 HttpSession 失败 principal={}: {}", principalName, e.getMessage());
        }
    }

    private SessionVO toSessionVO(OAuth2Authorization auth) {
        SessionVO vo = new SessionVO();
        vo.setAuthorizationId(auth.getId());
        vo.setPrincipalName(auth.getPrincipalName());
        vo.setRegisteredClientId(auth.getRegisteredClientId());
        vo.setGrantType(auth.getAuthorizationGrantType().getValue());
        vo.setClientName(resolveClientName(auth));

        OAuth2AccessToken at = unwrap(auth.getAccessToken());
        if (at != null) {
            if (at.getExpiresAt() != null)
                vo.setAccessTokenExpiresAt(FMT.format(at.getExpiresAt()));
            if (at.getIssuedAt() != null)
                vo.setLoginTime(FMT.format(at.getIssuedAt()));
            vo.setAccessToken(at.getTokenValue());
        }
        OAuth2RefreshToken rt = unwrap(auth.getRefreshToken());
        if (rt != null) {
            if (rt.getExpiresAt() != null)
                vo.setRefreshTokenExpiresAt(FMT.format(rt.getExpiresAt()));
            vo.setRefreshToken(rt.getTokenValue());
        }

        // 客户端 IP 和 User-Agent (登录时注入到 attributes, 见 RedisOAuth2AuthorizationService.enrichWithClientInfo)
        Object clientIp = auth.getAttributes().get("__client_ip");
        if (clientIp instanceof String ip && !ip.isBlank()) vo.setClientIp(ip);
        Object userAgent = auth.getAttributes().get("__user_agent");
        if (userAgent instanceof String ua && !ua.isBlank()) vo.setUserAgent(ua);

        return vo;
    }

    private String resolveClientName(OAuth2Authorization auth) {
        try {
            var client = clientRepository.findByClientId(auth.getRegisteredClientId());
            if (client != null) return client.getClientName();
        } catch (Exception ignored) {}
        return auth.getRegisteredClientId();
    }

    private String describeGrantType(String grantType) {
        return switch (grantType) {
            case "authorization_code" -> "授权码";
            case "password" -> "密码模式";
            case "client_credentials" -> "客户端凭证";
            case "refresh_token" -> "刷新令牌";
            case "urn:ietf:params:oauth:grant-type:device_code" -> "设备码";
            default -> grantType;
        };
    }
}
