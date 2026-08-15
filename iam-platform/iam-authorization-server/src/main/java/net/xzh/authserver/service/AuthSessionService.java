package net.xzh.authserver.service;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;
import net.xzh.authserver.security.repository.RedisOAuth2AuthorizationService;
import net.xzh.authserver.security.session.RedisSessionRegistry;
import net.xzh.authserver.vo.ClientSessionVO;
import net.xzh.authserver.vo.OnlineUserVO;
import net.xzh.authserver.vo.SessionVO;
import net.xzh.authserver.vo.SsoSessionVO;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthSessionService {

    private final RedisOAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository clientRepository;
    private final RedisSessionRegistry sessionRegistry;
    private final SysUserMapper userMapper;
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
     * 根据是否为管理员角色过滤在线用户。
     *
     * @param admin true=管理员列表，false=非管理员用户列表（如设备验证用户）
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
     * 下线指定用户所有会话: 删除 OAuth2 授权记录 + 终止 HttpSession.
     * <p>
     * 注意：会同时撤销 auth-server SSO HttpSession，用于管理端的真正"全部踢下线"场景。
     */
    public int revokeUserAll(String principalName) {
        invalidateHttpSessions(principalName);
        return authorizationService.revokeAllByPrincipal(principalName);
    }

    /**
     * 仅撤销用户的全部 OAuth2 授权令牌，不影响 auth-server 的 SSO HttpSession。
     * <p>
     * 用于客户端用户列表的"强制下线"按钮：该用户的所有 OAuth2 客户端会话失效，
     * 但 auth-server 的 SSO 会话保留，用户重新访问时可以通过 SSO 快速重新签发 token。
     */
    public int revokeClientTokensByPrincipal(String principalName) {
        return authorizationService.revokeAllByPrincipal(principalName);
    }

    /**
     * 下线单个 OAuth2 会话 (仅撤销 OAuth2Authorization 令牌)。
     */
    public boolean revokeSession(String authorizationId) {
        return authorizationService.revokeById(authorizationId);
    }

    /**
     * 下线单个 HttpSession（管理端/设备验证端会话）。
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
     * 下线指定类型的用户会话（管理端/设备验证端）。
     * <p>
     * 仅终止 HttpSession，不撤销 OAuth2 令牌。适用于管理端/设备验证端用户踢下线场景。
     * 通过 {@link RedisSessionRegistry#markSessionExpired(String)} 持久化过期标记。
     *
     * @param principalName  用户名
     * @param targetAdmin    true=仅踢管理员会话，false=仅踢非管理员会话（如设备验证用户）
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

    // ========= 统一在线管理 API (设计文档 §9) =========

    /**
     * 统一在线用户列表 (合并 SSO 会话 + 客户端会话数据).
     * <p>
     * 合并 RedisSessionRegistry (HttpSession) 和 RedisOAuth2AuthorizationService (OAuth2Authorization) 的数据,
     * 返回 User → SSO Session → Client Session 层级模型的最外层.
     */
    public List<OnlineUserVO> listOnlineUsersUnified() {
        // 1. 收集所有在线用户名 (来自 SSO 会话和 OAuth2 授权两个来源)
        Set<String> allPrincipals = new LinkedHashSet<>();
        // SSO 会话中的用户
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            String name = extractUsername(principal);
            if (name != null && !name.isBlank()) {
                allPrincipals.add(name);
            }
        }
        // OAuth2 授权中的用户
        allPrincipals.addAll(authorizationService.findAllOnlinePrincipals());

        // 2. 过滤: 只保留 sys_user 表中存在的用户 (排除 OAuth2 client_id 等非用户 principal)
        //    场景: OAuth2 token 端点会将 client_id 注册为 session principal,
        //    这些出现在 sessionRegistry.getAllPrincipals() 中但不是真正的用户
        //    V6.2: session principal name = 业务用户编码 user_code, 故按 user_code 反查
        List<OnlineUserVO> result = new ArrayList<>();
        for (String principal : allPrincipals) {
            SysUser user = userMapper.selectOne(new QueryWrapper<SysUser>().eq("user_code", principal));
            if (user == null) {
                log.debug("跳过非用户 principal: {}", principal);
                continue;
            }

            OnlineUserVO vo = new OnlineUserVO();
            vo.setUsername(principal);
            vo.setUserId(user.getId());
            vo.setNickname(user.getNickname());
            vo.setUserLabel(user.getUserLabel());            vo.setEnabled(user.getEnabled());

            // SSO 会话数
            List<SessionInformation> ssoSessions = getSessionsForPrincipal(principal);
            vo.setSsoSessionCount(ssoSessions.size());

            // 客户端会话数 + 客户端列表 + 最近访问时间
            List<OAuth2Authorization> clientAuths = authorizationService.findByPrincipal(principal);
            vo.setClientSessionCount(clientAuths.size());
            vo.setClients(clientAuths.stream()
                    .map(this::resolveClientName)
                    .filter(c -> c != null && !c.isEmpty())
                    .distinct()
                    .toList());

            // 最近访问时间: 取 SSO 会话和客户端会话中最新的时间
            String lastAccess = "-";
            if (!ssoSessions.isEmpty()) {
                lastAccess = ssoSessions.stream()
                        .map(SessionInformation::getLastRequest)
                        .filter(java.util.Objects::nonNull)
                        .map(d -> FMT.format(Instant.ofEpochMilli(d.getTime()).atZone(ZoneId.systemDefault())))
                        .max(String::compareTo)
                        .orElse("-");
            }
            if (!clientAuths.isEmpty()) {
                String clientLast = clientAuths.stream()
                        .map(a -> unwrap(a.getAccessToken()))
                        .filter(t -> t != null && t.getIssuedAt() != null)
                        .map(t -> FMT.format(t.getIssuedAt()))
                        .max(String::compareTo)
                        .orElse("-");
                if (clientLast.compareTo(lastAccess) > 0) {
                    lastAccess = clientLast;
                }
            }
            vo.setLastAccessTime(lastAccess);

            result.add(vo);
        }
        return result;
    }

    /**
     * 指定用户的 SSO 会话层级视图 (含嵌套的客户端会话).
     */
    public List<SsoSessionVO> listSsoSessionsByUserId(Long userId) {
        SysUser user = userMapper.selectById(userId);
        if (user == null) return List.of();
        String userCode = user.getUserCode();
        List<SsoSessionVO> result = new ArrayList<>();
        for (SessionInformation si : getSessionsForPrincipal(userCode)) {
            SsoSessionVO vo = new SsoSessionVO();
            vo.setSessionId(si.getSessionId());
            vo.setPrincipalName(userCode);
            vo.setExpired(si.isExpired());
            // 登录时间 = 会话创建时间 (creationTime, 仅在 registerNewSession 时写入, 不会更新)
            Long creationTime = sessionRegistry.getCreationTime(si.getSessionId());
            if (creationTime != null) {
                vo.setLoginTime(FMT.format(Instant.ofEpochMilli(creationTime).atZone(ZoneId.systemDefault())));
            }
            // 最近访问时间 = lastRequest (每次请求都会更新)
            if (si.getLastRequest() != null) {
                vo.setLastAccessTime(FMT.format(Instant.ofEpochMilli(si.getLastRequest().getTime()).atZone(ZoneId.systemDefault())));
            }

            // 拉取该 SSO 会话下的客户端会话
            List<OAuth2Authorization> clientAuths = authorizationService.findBySsoSessionId(si.getSessionId());
            vo.setClientSessions(clientAuths.stream().map(this::toClientSessionVO).toList());

            result.add(vo);
        }
        return result;
    }

    /**
     * 按用户 ID 踢下线 (撤销所有 SSO 会话 + 客户端会话).
     */
    public int revokeUserAllById(Long userId) {
        SysUser user = userMapper.selectById(userId);
        if (user == null) return 0;
        return revokeUserAll(user.getUserCode());
    }

    /**
     * 按 SSO 会话踢下线 (终止指定 SSO 会话 + 撤销其关联的客户端会话).
     */
    public boolean revokeSsoSession(String ssoSessionId) {
        try {
            // 1. 标记 SSO 会话过期 (SessionExpirationFilter 会在下次请求时销毁)
            sessionRegistry.markSessionExpired(ssoSessionId);
            // 2. 撤销该 SSO 会话关联的所有 OAuth2 授权
            int revoked = authorizationService.revokeBySsoSessionId(ssoSessionId);
            log.info("按 SSO 会话踢下线: ssoSessionId={}, 撤销客户端会话数={}", ssoSessionId, revoked);
            return true;
        } catch (Exception e) {
            log.warn("按 SSO 会话踢下线失败 ssoSessionId={}: {}", ssoSessionId, e.getMessage());
            return false;
        }
    }

    /**
     * 通过 SessionRegistry 终止用户的所有 HttpSession。
     */
    private void invalidateHttpSessions(String principalName) {
        try {
            for (Object principal : sessionRegistry.getAllPrincipals()) {
                if (principal instanceof User user && principalName.equals(user.getUsername())) {
                    for (SessionInformation session : sessionRegistry.getAllSessions(user, true)) {
                        // 关键修复: 除了内存中标记过期，还必须持久化到 Redis，
                        // 否则用户下次请求时 SessionExpirationFilter 检测不到过期状态
                        session.expireNow();
                        sessionRegistry.markSessionExpired(session.getSessionId());
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

    /**
     * 将 OAuth2Authorization 转换为 ClientSessionVO (层级视图用, 精简掉 token 值).
     */
    private ClientSessionVO toClientSessionVO(OAuth2Authorization auth) {
        ClientSessionVO vo = new ClientSessionVO();
        vo.setAuthorizationId(auth.getId());
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
            vo.setRefreshToken(rt.getTokenValue());
        }

        Object clientIp = auth.getAttributes().get("__client_ip");
        if (clientIp instanceof String ip && !ip.isBlank()) vo.setClientIp(ip);
        Object userAgent = auth.getAttributes().get("__user_agent");
        if (userAgent instanceof String ua && !ua.isBlank()) vo.setUserAgent(ua);
        Object ssoSessionId = auth.getAttributes().get(RedisOAuth2AuthorizationService.ATTR_SSO_SESSION_ID);
        if (ssoSessionId instanceof String sid && !sid.isBlank()) vo.setSsoSessionId(sid);

        return vo;
    }

    /**
     * 从 principal 对象提取用户名.
     */
    private String extractUsername(Object principal) {
        if (principal instanceof UserDetails ud) {
            return ud.getUsername();
        }
        if (principal instanceof String s) {
            return s;
        }
        if (principal != null) {
            return principal.toString();
        }
        return null;
    }

    /**
     * 按用户名从 SessionRegistry 获取该用户的所有会话.
     * 构建 UserDetails 桩对象用于查询, includeExpired=true 以显示被标记过期的会话.
     */
    private List<SessionInformation> getSessionsForPrincipal(String principalName) {
        try {
            // V6.2: principal name = 业务用户编码 user_code; 查询 user_code 确认是真实用户
            SysUser user = userMapper.selectOne(new QueryWrapper<SysUser>().eq("user_code", principalName));
            String authority = (user != null && "admin".equals(user.getUserLabel()))
                    ? "ROLE_ADMIN" : "ROLE_USER";
            UserDetails userDetails = User.withUsername(principalName)
                    .password("[PROTECTED]")
                    .authorities(new SimpleGrantedAuthority(authority))
                    .build();
            return sessionRegistry.getAllSessions(userDetails, true);
        } catch (Exception e) {
            log.warn("获取用户会话失败 principal={}: {}", principalName, e.getMessage());
            return List.of();
        }
    }

    private String resolveClientName(OAuth2Authorization auth) {
        try {
            // getRegisteredClientId() 是内部注册 id (如 "2"), 需按 id 查询取 client_id / client_name
            var client = clientRepository.findById(auth.getRegisteredClientId());
            if (client != null) {
                String name = client.getClientName();
                if (name != null && !name.isBlank()) return name;
                return client.getClientId();
            }
        } catch (Exception ignored) {}
        return auth.getRegisteredClientId();
    }
}
