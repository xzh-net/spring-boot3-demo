package net.xzh.authserver.service;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.session.RedisSessionRegistry;
import net.xzh.authserver.vo.SessionVO;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthSessionService {

    private final RedisOAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final RedisSessionRegistry sessionRegistry;
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    private static <T extends OAuth2Token> T unwrap(
            OAuth2Authorization.Token<T> wrapper) {
        return wrapper != null ? wrapper.getToken() : null;
    }

    /**
     * 客户端在线用户列表（OAuth2 对接进来的用户）。
     */
    public List<Map<String, Object>> listOnlineUsers() {
        Set<String> principals = authorizationService.findAllOnlinePrincipals();
        List<Map<String, Object>> result = new ArrayList<>();
        for (String principal : principals) {
            List<OAuth2Authorization> sessions = authorizationService.findByPrincipal(principal);
            if (sessions.isEmpty()) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("principalName", principal);
            row.put("sessionCount", sessions.size());

            row.put("loginTime", sessions.stream()
                    .map(a -> unwrap(a.getAccessToken()))
                    .filter(t -> t != null && t.getIssuedAt() != null)
                    .map(t -> FMT.format(t.getIssuedAt()))
                    .min(String::compareTo).orElse("-"));

            row.put("lastAccessTime", sessions.stream()
                    .map(a -> unwrap(a.getAccessToken()))
                    .filter(t -> t != null && t.getIssuedAt() != null)
                    .map(t -> FMT.format(t.getIssuedAt()))
                    .max(String::compareTo).orElse("-"));

            row.put("clients", sessions.stream()
                    .map(this::resolveClientName)
                    .filter(c -> c != null && !c.isEmpty())
                    .distinct()
                    .reduce((a, b) -> a + ", " + b)
                    .orElse("-"));

            row.put("grantTypes", sessions.stream()
                    .map(a -> a.getAuthorizationGrantType().getValue())
                    .distinct()
                    .toList());

            result.add(row);
        }
        return result;
    }

    /**
     * 管理端在线用户列表（通过 SessionRegistry 获取，持久化到 Redis）。
     * <p>
     * 过滤条件：用户拥有 ROLE_ADMIN 权限。
     */
    public List<Map<String, Object>> listAdminOnlineUsers() {
        return filterSessionUsers(true);
    }

    /**
     * 门户端在线用户列表（通过 SessionRegistry 获取，持久化到 Redis）。
     * <p>
     * 过滤条件：用户不拥有 ROLE_ADMIN 权限。
     */
    public List<Map<String, Object>> listPortalOnlineUsers() {
        return filterSessionUsers(false);
    }

    /**
     * 根据是否为管理员角色过滤在线用户。
     *
     * @param admin true=管理员列表，false=门户用户列表
     */
    private List<Map<String, Object>> filterSessionUsers(boolean admin) {
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            for (Object principal : sessionRegistry.getAllPrincipals()) {
                if (!(principal instanceof UserDetails userDetails)) {
                    continue;
                }
                boolean isAdmin = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .anyMatch(ROLE_ADMIN::equals);
                // 根据角色过滤
                if (admin != isAdmin) {
                    continue;
                }
                String username = userDetails.getUsername();
                List<SessionInformation> sessions = sessionRegistry.getAllSessions(userDetails, false);
                if (sessions.isEmpty()) {
                    continue;
                }
                for (SessionInformation session : sessions) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("principalName", username);
                    row.put("sessionId", session.getSessionId());
                    if (session.getLastRequest() != null) {
                        Instant instant = Instant.ofEpochMilli(session.getLastRequest().getTime());
                        row.put("loginTime", FMT.format(instant.atZone(ZoneId.systemDefault())));
                        row.put("lastAccessTime", FMT.format(instant.atZone(ZoneId.systemDefault())));
                    } else {
                        row.put("loginTime", "-");
                        row.put("lastAccessTime", "-");
                    }
                    row.put("sessionCount", sessions.size());
                    result.add(row);
                }
            }
        } catch (Exception e) {
            log.warn("获取Session用户列表失败: {}", e.getMessage());
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
     */
    public int revokeUserAll(String principalName) {
        invalidateHttpSessions(principalName);
        return authorizationService.revokeAllByPrincipal(principalName);
    }

    /**
     * 下线单个 OAuth2 会话 (仅撤销 OAuth2Authorization 令牌)。
     */
    public boolean revokeSession(String authorizationId) {
        return authorizationService.revokeById(authorizationId);
    }

    /**
     * 下线单个 HttpSession（管理端/门户端会话）。
     * <p>
     * 通过 {@link RedisSessionRegistry#markSessionExpired(String)} 将过期标记持久化到 Redis，
     * 确保多节点部署时所有节点都能检测到过期状态。
     * <p>
     * <b>不能</b>调用 removeSessionInformation，否则 SessionExpirationFilter 将无法通过
     * getSessionInformation 检测到过期状态。SessionExpirationFilter 会在用户下次请求时
     * 检测到过期，自动销毁 session 并清理记录。
     *
     * @param sessionId 会话 ID
     * @return 是否成功
     */
    public boolean revokeHttpSession(String sessionId) {
        try {
            SessionInformation sessionInfo = sessionRegistry.getSessionInformation(sessionId);
            if (sessionInfo != null && !sessionInfo.isExpired()) {
                // 持久化过期标记到 Redis，所有节点可见
                sessionRegistry.markSessionExpired(sessionId);
                log.info("已标记 HttpSession 过期（持久化到Redis）sessionId={}, 等待 SessionExpirationFilter 销毁", sessionId);
                return true;
            }
            return false;
        } catch (Exception e) {
            log.warn("终止 HttpSession 失败 sessionId={}: {}", sessionId, e.getMessage());
            return false;
        }
    }

    /**
     * 下线指定类型的用户会话（管理端/门户端）。
     * <p>
     * 仅终止 HttpSession，不撤销 OAuth2 令牌。适用于管理端/门户端用户踢下线场景。
     * 通过 {@link RedisSessionRegistry#markSessionExpired(String)} 持久化过期标记。
     *
     * @param principalName  用户名
     * @param targetAdmin    true=仅踢管理员会话，false=仅踢门户用户会话
     * @return 被终止的会话数
     */
    public int revokeSessionUser(String principalName, boolean targetAdmin) {
        int count = 0;
        try {
            for (Object principal : sessionRegistry.getAllPrincipals()) {
                if (!(principal instanceof UserDetails userDetails)) {
                    continue;
                }
                boolean isAdmin = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .anyMatch(ROLE_ADMIN::equals);
                // 角色不匹配则跳过
                if (targetAdmin != isAdmin) {
                    continue;
                }
                if (!principalName.equals(userDetails.getUsername())) {
                    continue;
                }
                for (SessionInformation session : sessionRegistry.getAllSessions(userDetails, true)) {
                    if (session.isExpired()) {
                        continue; // 已过期，跳过
                    }
                    // 持久化过期标记到 Redis，所有节点可见
                    sessionRegistry.markSessionExpired(session.getSessionId());
                    count++;
                    log.info("已标记用户 HttpSession 过期（持久化到Redis）principal={}, sessionId={}, 等待 Filter 销毁",
                            principalName, session.getSessionId());
                }
            }
        } catch (Exception e) {
            log.warn("终止用户会话失败 principal={}: {}", principalName, e.getMessage());
        }
        return count;
    }

    /**
     * 下线指定用户在指定客户端上的所有会话。
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
     * 通过 SessionRegistry 终止用户的所有 HttpSession。
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
