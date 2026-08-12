package net.xzh.authserver.security.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Redis 持久化的 OAuth2AuthorizationService 实现.
 * <p>
 * 职责：
 * 1. 将 OAuth2 授权数据（authorization codes、access tokens、refresh tokens、device codes）
 *    序列化存入 Redis，TTL 与 token 过期时间对齐。
 * 2. 维护 token → authorizationId 的反向索引，支持按 token 值快速查找授权记录。
 * 3. 维护 principal → authorizationId Set 索引，支持在线会话查询和强制下线。
 * 4. token 撤销时直接删除 Redis 记录（Opaque 模式无需黑名单）。
 *
 * 架构定位：
 * 属于 repository 层，实现 SAS 的 OAuth2AuthorizationService 接口。
 * 与 JdbcRegisteredClientRepository（客户端配置）和 JdbcOAuth2AuthorizationConsentService（授权同意）
 * 协同工作，后两者使用 MySQL 持久化。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public final class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    /** Redis key 前缀：授权记录主存储 */
    private static final String KEY_PREFIX = "oauth2:auth:";
    /** Redis key 前缀：用户 → 授权 ID 集合索引 */
    private static final String USER_INDEX_PREFIX = "oauth2:user:";
    /** Redis key 前缀：SSO 会话 → 授权 ID 集合索引 */
    private static final String SSO_SESSION_INDEX_PREFIX = "oauth2:sso_session:";
    /** OAuth2Authorization attribute 中存 SSO HttpSession ID 的 key */
    public static final String ATTR_SSO_SESSION_ID = "__sso_session_id";

    /** Redis 操作模板，用于持久化授权数据 */
    private final StringRedisTemplate redisTemplate;
    /** JSON 序列化/反序列化工具 */
    private final ObjectMapper objectMapper;
    /** 客户端仓库，用于判断 principalName 是否为 clientId */
    private final RegisteredClientRepository clientRepository;

    private static <T extends OAuth2Token> T unwrap(
            OAuth2Authorization.Token<T> wrapper) {
        return wrapper != null ? wrapper.getToken() : null;
    }

    /**
     * 从当前 HTTP 请求提取客户端公网 IP 和 User-Agent, 注入到 OAuth2Authorization 的 attributes.
     * 仅在 web 请求线程内有效 (SAS 的 filter 链调 save 时满足此条件);
     * 非请求线程 (如后台任务) 拿不到则原样返回, 不影响已有 attributes.
     */
    private OAuth2Authorization enrichWithClientInfo(OAuth2Authorization authorization) {
        try {
            var reqAttrs = RequestContextHolder.getRequestAttributes();
            if (!(reqAttrs instanceof ServletRequestAttributes sra)) {
                return authorization;
            }
            HttpServletRequest req = sra.getRequest();
            String clientIp = resolveClientIp(req);
            String userAgent = req.getHeader("User-Agent");
            // 注入 SSO 会话 ID (HttpSession ID), 用于建立 User → SSO Session → Client Session 层级关联.
            // 仅在 authorization 尚未包含此属性时才注入, 避免 token 刷新 (BFF 服务器对服务器调用, 无用户 session) 时覆盖原值.
            String existingSsoSessionId = (String) authorization.getAttributes().get(ATTR_SSO_SESSION_ID);
            String ssoSessionId = existingSsoSessionId;
            if (ssoSessionId == null || ssoSessionId.isBlank()) {
                jakarta.servlet.http.HttpSession httpSession = req.getSession(false);
                if (httpSession != null) {
                    ssoSessionId = httpSession.getId();
                }
            }
            // IP / User-Agent 同样只在首次写入, 后续 save() (如换 token / 刷新的服务器对服务器调用,
            // 携带的是 BFF 应用服务器 IP 和无浏览器 UA) 不覆盖浏览器授权请求时记录的原始值.
            Map<String, Object> attrs = authorization.getAttributes();
            String existingClientIp = (String) attrs.get("__client_ip");
            String existingUserAgent = (String) attrs.get("__user_agent");
            if (existingClientIp != null && !existingClientIp.isBlank()) clientIp = existingClientIp;
            if (existingUserAgent != null && !existingUserAgent.isBlank()) userAgent = existingUserAgent;

            if (clientIp == null && userAgent == null && ssoSessionId == null) return authorization;
            OAuth2Authorization.Builder b = OAuth2Authorization.from(authorization);
            if (clientIp != null) b.attribute("__client_ip", clientIp);
            if (userAgent != null) b.attribute("__user_agent", userAgent);
            if (ssoSessionId != null && !ssoSessionId.isBlank()) {
                b.attribute(ATTR_SSO_SESSION_ID, ssoSessionId);
            }
            return b.build();
        } catch (Exception e) {
            return authorization;
        }
    }

    /**
     * 解析客户端公网 IP: 优先取反向代理链路头 (X-Forwarded-For 首个 / X-Real-IP),
     * 退而求其次用 HttpServletRequest.getRemoteAddr().
     * <p>
     * 返回前统一规整地址格式:
     *   - IPv6 回环 (::1 / 0:0:0:0:0:0:0:1) → 127.0.0.1, 避免各请求因 IPv6/IPv4 栈不同显示不一致
     *   - IPv4-mapped IPv6 (::ffff:192.168.1.5) → 还原为 192.168.1.5
     *   - 剥离 IPv6 链路本地地址的 zone 索引 (fe80::1%eth0 → fe80::1)
     */
    private String resolveClientIp(HttpServletRequest req) {
        String ip = null;
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty()) {
            ip = xff.split(",")[0].trim();
        }
        if (ip == null || ip.isEmpty()) {
            String xri = req.getHeader("X-Real-IP");
            if (xri != null && !xri.isEmpty()) ip = xri.trim();
        }
        if (ip == null || ip.isEmpty()) {
            ip = req.getRemoteAddr();
        }
        return normalizeIp(ip);
    }

    /** 规整 IP 展示格式, 使各条记录的来源/形态一致. */
    private String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) return null;
        ip = ip.trim();
        int zoneIdx = ip.indexOf('%');
        if (zoneIdx > 0) ip = ip.substring(0, zoneIdx);
        String lower = ip.toLowerCase();
        if ("::1".equals(lower) || "0:0:0:0:0:0:0:1".equals(lower)) {
            return "127.0.0.1";
        }
        if (lower.startsWith("::ffff:")) {
            String v4 = ip.substring(7);
            if (v4.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return v4;
        }
        return ip;
    }

    // ------------------------------------------------------------------
    // OAuth2AuthorizationService 标准接口
    // ------------------------------------------------------------------

    @Override
    public void save(OAuth2Authorization authorization) {
        try {
            String id = authorization.getId();
            String principalName = authorization.getPrincipalName();
            String registeredClientId = authorization.getRegisteredClientId();

            // 注入客户端公网 IP 和 User-Agent 到 attributes (供在线会话列表展示)
            // SAS 在 web 请求线程内调 save, 可通过 RequestContextHolder 获取当前请求
            authorization = enrichWithClientInfo(authorization);

            // 检测 SAS 标准吊销: /oauth2/revoke 会调 save() 传入 invalidated=true 的 token,
            // access_token 已改用 Opaque, 直接删除 Redis 授权记录即可让 introspect 返回 401,
            // 无需再维护 JWT 黑名单.
            boolean accessInvalidated = authorization.getAccessToken() != null
                    && authorization.getAccessToken().isInvalidated();
            boolean refreshInvalidated = authorization.getRefreshToken() != null
                    && authorization.getRefreshToken().isInvalidated();

            if (accessInvalidated || refreshInvalidated) {
                log.info("检测到 token invalidated 标记, 删除授权记录 authId={}", id);
                remove(authorization);
                return;
            }

            String json = objectMapper.writeValueAsString(serialize(authorization));

            Duration ttl = computeTtl(authorization);
            redisTemplate.opsForValue().set(KEY_PREFIX + "id:" + id, json, ttl.toMillis(), TimeUnit.MILLISECONDS);

            OAuth2AccessToken accessToken = unwrap(authorization.getAccessToken());
            if (accessToken != null && accessToken.getTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "access:" + accessToken.getTokenValue(),
                        id,
                        computeTtlForToken(accessToken.getExpiresAt()).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            OAuth2RefreshToken refreshToken = unwrap(authorization.getRefreshToken());
            if (refreshToken != null && refreshToken.getTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "refresh:" + refreshToken.getTokenValue(),
                        id,
                        computeTtlForToken(refreshToken.getExpiresAt()).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            OAuth2AuthorizationCode authorizationCode = unwrap(authorization.getToken(OAuth2AuthorizationCode.class));
            if (authorizationCode != null && authorizationCode.getTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "code:" + authorizationCode.getTokenValue(),
                        id,
                        computeTtlForToken(authorizationCode.getExpiresAt()).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            OAuth2DeviceCode deviceCode = unwrap(authorization.getToken(OAuth2DeviceCode.class));
            if (deviceCode != null && deviceCode.getTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "device:" + deviceCode.getTokenValue(),
                        id,
                        computeTtlForToken(deviceCode.getExpiresAt()).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            OAuth2UserCode userCode = unwrap(authorization.getToken(OAuth2UserCode.class));
            if (userCode != null && userCode.getTokenValue() != null) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "user_code:" + userCode.getTokenValue(),
                        id,
                        computeTtlForToken(userCode.getExpiresAt()).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            Object state = authorization.getAttributes().get("state");
            if (state instanceof String s && StringUtils.hasText(s)) {
                redisTemplate.opsForValue().set(
                        KEY_PREFIX + "state:" + s,
                        id,
                        Duration.ofMinutes(5).toMillis(),
                        TimeUnit.MILLISECONDS);
            }

            // 设备码 token 轮询阶段 SAS 会用 client_id 作为 principalName 创建授权,
            // 此时 principalName 不是真的用户, 不应写入用户索引污染在线用户列表.
            if (StringUtils.hasText(principalName) && !isClientId(principalName)) {
                redisTemplate.opsForSet().add(USER_INDEX_PREFIX + principalName, id);
                redisTemplate.expire(USER_INDEX_PREFIX + principalName, ttl.toMillis(), TimeUnit.MILLISECONDS);
            }

            // 维护 SSO 会话 → 授权 ID 索引, 用于按 SSO 会话反查客户端会话 (层级视图 + 按会话踢下线)
            Object ssoSessionIdAttr = authorization.getAttributes().get(ATTR_SSO_SESSION_ID);
            if (ssoSessionIdAttr instanceof String ssoSessionId && StringUtils.hasText(ssoSessionId)) {
                redisTemplate.opsForSet().add(SSO_SESSION_INDEX_PREFIX + ssoSessionId, id);
                redisTemplate.expire(SSO_SESSION_INDEX_PREFIX + ssoSessionId, ttl.toMillis(), TimeUnit.MILLISECONDS);
            }

            log.debug("OAuth2Authorization saved to Redis, id={}, user={}", id, principalName);
        } catch (Exception e) {
            log.error("保存 OAuth2Authorization 到 Redis 失败", e);
            throw new RuntimeException("保存授权信息失败", e);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        try {
            String id = authorization.getId();
            String principalName = authorization.getPrincipalName();
            redisTemplate.delete(KEY_PREFIX + "id:" + id);

            OAuth2AccessToken accessToken = unwrap(authorization.getAccessToken());
            if (accessToken != null && accessToken.getTokenValue() != null) {
                redisTemplate.delete(KEY_PREFIX + "access:" + accessToken.getTokenValue());
            }
            OAuth2RefreshToken refreshToken = unwrap(authorization.getRefreshToken());
            if (refreshToken != null && refreshToken.getTokenValue() != null) {
                redisTemplate.delete(KEY_PREFIX + "refresh:" + refreshToken.getTokenValue());
            }
            OAuth2AuthorizationCode code = unwrap(authorization.getToken(OAuth2AuthorizationCode.class));
            if (code != null && code.getTokenValue() != null) {
                redisTemplate.delete(KEY_PREFIX + "code:" + code.getTokenValue());
            }
            OAuth2DeviceCode deviceCode = unwrap(authorization.getToken(OAuth2DeviceCode.class));
            if (deviceCode != null && deviceCode.getTokenValue() != null) {
                redisTemplate.delete(KEY_PREFIX + "device:" + deviceCode.getTokenValue());
            }
            OAuth2UserCode userCode = unwrap(authorization.getToken(OAuth2UserCode.class));
            if (userCode != null && userCode.getTokenValue() != null) {
                redisTemplate.delete(KEY_PREFIX + "user_code:" + userCode.getTokenValue());
            }
            Object state = authorization.getAttributes().get("state");
            if (state instanceof String s && StringUtils.hasText(s)) {
                redisTemplate.delete(KEY_PREFIX + "state:" + s);
            }

            if (StringUtils.hasText(principalName)) {
                // 注意: SetOperations.remove(key, member) 返回的是"被删除的成员数"(0或1),
                // 不是 Set 的剩余大小. 不能用它判断 Set 是否为空.
                // 并发场景下 (web-app 用 Promise.all 同时 revoke access_token + refresh_token),
                // 两个线程会同时 remove 同一个 authId, 第二个线程 srem 返回 0 (成员已不存在),
                // 若误判为 "Set 已空" 会 delete 整个 key, 导致该用户其他会话的索引丢失.
                redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + principalName, id);
                // 删除后用 size() 检查 Set 是否真的为空
                Long size = redisTemplate.opsForSet().size(USER_INDEX_PREFIX + principalName);
                if (size != null && size == 0) {
                    redisTemplate.delete(USER_INDEX_PREFIX + principalName);
                }
            }

            // 清理 SSO 会话索引 (与 USER_INDEX 清理逻辑一致, 注意并发用 size 检查)
            Object ssoSessionIdAttr = authorization.getAttributes().get(ATTR_SSO_SESSION_ID);
            if (ssoSessionIdAttr instanceof String ssoSessionId && StringUtils.hasText(ssoSessionId)) {
                redisTemplate.opsForSet().remove(SSO_SESSION_INDEX_PREFIX + ssoSessionId, id);
                Long ssoSize = redisTemplate.opsForSet().size(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
                if (ssoSize != null && ssoSize == 0) {
                    redisTemplate.delete(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
                }
            }
        } catch (Exception e) {
            log.error("删除 OAuth2Authorization 失败", e);
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        String json = redisTemplate.opsForValue().get(KEY_PREFIX + "id:" + id);
        return deserialize(json);
    }

    /**
     * 判断 principalName 是否是已注册的客户端 ID (而非真实用户名).
     * 设备码 token 轮询阶段 SAS 会用 client_id 作为 principalName, 此时不应写入用户索引.
     */
    private boolean isClientId(String principalName) {
        try {
            return clientRepository.findByClientId(principalName) != null;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (!StringUtils.hasText(token)) return null;
        String id = null;

        if (tokenType == null) {
            id = redisTemplate.opsForValue().get(KEY_PREFIX + "access:" + token);
            if (id == null) id = redisTemplate.opsForValue().get(KEY_PREFIX + "refresh:" + token);
            if (id == null) id = redisTemplate.opsForValue().get(KEY_PREFIX + "code:" + token);
            if (id == null) id = redisTemplate.opsForValue().get(KEY_PREFIX + "device:" + token);
            if (id == null) id = redisTemplate.opsForValue().get(KEY_PREFIX + "user_code:" + token);
            if (id == null) id = redisTemplate.opsForValue().get(KEY_PREFIX + "state:" + token);
        } else {
            String key = switch (tokenType.getValue()) {
                case "access_token" -> KEY_PREFIX + "access:" + token;
                case "refresh_token" -> KEY_PREFIX + "refresh:" + token;
                case "code" -> KEY_PREFIX + "code:" + token;
                case "device_code" -> KEY_PREFIX + "device:" + token;
                case "user_code" -> KEY_PREFIX + "user_code:" + token;
                case "state" -> KEY_PREFIX + "state:" + token;
                default -> null;
            };
            if (key != null) id = redisTemplate.opsForValue().get(key);
        }

        return id != null ? findById(id) : null;
    }

    // ------------------------------------------------------------------
    // 运行时查询 / 强制下线 API (给管理端使用)
    // ------------------------------------------------------------------

    public Set<String> findAllOnlinePrincipals() {
        Set<String> result = new HashSet<>();
        String pattern = USER_INDEX_PREFIX + "*";
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).count(100).build();
            try (Cursor<byte[]> cursor = connection.scan(options)) {
                while (cursor.hasNext()) {
                    String key = new String(cursor.next());
                    String principal = key.substring(USER_INDEX_PREFIX.length());
                    result.add(principal);
                }
            }
            return null;
        });
        return result;
    }

    public List<OAuth2Authorization> findByPrincipal(String principalName) {
        Set<String> ids = redisTemplate.opsForSet().members(USER_INDEX_PREFIX + principalName);
        if (ids == null || ids.isEmpty()) return List.of();
        
        List<OAuth2Authorization> list = new ArrayList<>();
        List<String> staleIds = new ArrayList<>(); // 收集无效的 ID，用于后续清理
        
        for (String id : ids) {
            OAuth2Authorization auth = findById(id);
            // 如果授权记录不存在 (已过期/被删除)，视为僵尸 ID
            if (auth == null) {
                staleIds.add(id);
                continue;
            }
            
            // 过滤: principalName 必须匹配 (防止并发或设备码流程残留)
            if (!principalName.equals(auth.getPrincipalName())) {
                staleIds.add(id);
                continue;
            }
            
            // 检查是否有有效的 Token
            if (!hasValidToken(auth)) {
                staleIds.add(id);
                continue;
            }
            
            list.add(auth);
        }
        
        // 主动清理 Set 中的僵尸 ID，确保会话数统计的准确性
        if (!staleIds.isEmpty()) {
            log.info("清理 principal={} 的 {} 个无效授权记录", principalName, staleIds.size());
            for (String staleId : staleIds) {
                redisTemplate.opsForSet().remove(USER_INDEX_PREFIX + principalName, staleId);
            }
            // 清理后检查 Set 是否为空，若是则删除整个 Set Key
            Long remaining = redisTemplate.opsForSet().size(USER_INDEX_PREFIX + principalName);
            if (remaining != null && remaining == 0) {
                redisTemplate.delete(USER_INDEX_PREFIX + principalName);
            }
        }
        
        return list;
    }

    /**
     * 判断 OAuth2Authorization 是否拥有有效的 token (非空且未失效)
     */
    private boolean hasValidToken(OAuth2Authorization auth) {
        OAuth2Authorization.Token<OAuth2AccessToken> atWrapper = auth.getAccessToken();
        if (atWrapper != null && atWrapper.getToken() != null && !atWrapper.isInvalidated()) {
            return true;
        }
        OAuth2Authorization.Token<OAuth2RefreshToken> rtWrapper = auth.getRefreshToken();
        return rtWrapper != null && rtWrapper.getToken() != null && !rtWrapper.isInvalidated();
    }

    public List<OAuth2Authorization> findByClientId(String registeredClientId) {
        List<OAuth2Authorization> result = new ArrayList<>();
        String pattern = KEY_PREFIX + "id:*";
        redisTemplate.execute((RedisCallback<Void>) connection -> {
            ScanOptions options = ScanOptions.scanOptions().match(pattern).count(100).build();
            try (Cursor<byte[]> cursor = connection.scan(options)) {
                while (cursor.hasNext()) {
                    String key = new String(cursor.next());
                    String id = key.substring((KEY_PREFIX + "id:").length());
                    OAuth2Authorization auth = findById(id);
                    if (auth != null && registeredClientId.equals(auth.getRegisteredClientId())) {
                        result.add(auth);
                    }
                }
            }
            return null;
        });
        return result;
    }

    public int revokeAllByPrincipal(String principalName) {
        Set<String> ids = redisTemplate.opsForSet().members(USER_INDEX_PREFIX + principalName);
        if (ids == null || ids.isEmpty()) return 0;

        int count = 0;
        for (String id : ids) {
            OAuth2Authorization auth = findById(id);
            if (auth != null) {
                remove(auth);
                count++;
            } else {
                // 反序列化失败也要清理残留的 id 键
                redisTemplate.delete(KEY_PREFIX + "id:" + id);
            }
        }
        redisTemplate.delete(USER_INDEX_PREFIX + principalName);
        log.info("强制下线 principal={}, 会话数={}", principalName, count);
        return count;
    }

    public boolean revokeById(String authorizationId) {
        OAuth2Authorization auth = findById(authorizationId);
        if (auth == null) return false;
        remove(auth);
        return true;
    }

    /**
     * 查询指定 SSO 会话下的所有 OAuth2 授权 (客户端会话).
     * <p>
     * 用于管理端层级视图 (User → SSO Session → Client Session) 和按 SSO 会话踢下线.
     *
     * @param ssoSessionId SSO HttpSession ID
     * @return 该 SSO 会话关联的 OAuth2Authorization 列表
     */
    public List<OAuth2Authorization> findBySsoSessionId(String ssoSessionId) {
        if (!StringUtils.hasText(ssoSessionId)) return List.of();
        Set<String> ids = redisTemplate.opsForSet().members(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
        if (ids == null || ids.isEmpty()) return List.of();

        List<OAuth2Authorization> list = new ArrayList<>();
        List<String> staleIds = new ArrayList<>();
        for (String id : ids) {
            OAuth2Authorization auth = findById(id);
            if (auth == null) {
                staleIds.add(id);
                continue;
            }
            // 校验 SSO 会话 ID 仍匹配 (防止索引残留)
            Object attr = auth.getAttributes().get(ATTR_SSO_SESSION_ID);
            if (!ssoSessionId.equals(attr)) {
                staleIds.add(id);
                continue;
            }
            // 检查是否有有效的 Token — 过滤掉仅含授权码 (prompt=none 静默 SSO 探测等) 的授权,
            // 避免在线会话层级视图出现 "空 token" 的客户端会话
            if (!hasValidToken(auth)) {
                staleIds.add(id);
                continue;
            }
            list.add(auth);
        }
        // 清理僵尸 ID
        if (!staleIds.isEmpty()) {
            for (String staleId : staleIds) {
                redisTemplate.opsForSet().remove(SSO_SESSION_INDEX_PREFIX + ssoSessionId, staleId);
            }
            Long remaining = redisTemplate.opsForSet().size(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
            if (remaining != null && remaining == 0) {
                redisTemplate.delete(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
            }
        }
        return list;
    }

    /**
     * 撤销指定 SSO 会话下的所有 OAuth2 授权.
     * <p>
     * 用于全局退出: 仅撤销当前 SSO 会话关联的客户端会话, 不影响该用户其他设备的 SSO 会话.
     *
     * @param ssoSessionId SSO HttpSession ID
     * @return 撤销的授权数量
     */
    public int revokeBySsoSessionId(String ssoSessionId) {
        if (!StringUtils.hasText(ssoSessionId)) return 0;
        List<OAuth2Authorization> auths = findBySsoSessionId(ssoSessionId);
        int count = 0;
        for (OAuth2Authorization auth : auths) {
            remove(auth);
            count++;
        }
        // 确保索引键被清理
        redisTemplate.delete(SSO_SESSION_INDEX_PREFIX + ssoSessionId);
        if (count > 0) {
            log.info("按 SSO 会话撤销授权: ssoSessionId={}, 撤销数={}", ssoSessionId, count);
        }
        return count;
    }

    /**
     * 直接吊销已加载的 OAuth2Authorization (避免重复 findById 查询)。
     * access_token 改用 Opaque 后, 删 Redis key 即让 introspect 返回 401, 无需黑名单。
     */
    public void revoke(OAuth2Authorization auth) {
        if (auth == null) return;
        remove(auth);
    }

    // ------------------------------------------------------------------
    // 序列化 / 反序列化
    // ------------------------------------------------------------------

    private Map<String, Object> serialize(OAuth2Authorization auth) throws Exception {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", auth.getId());
        map.put("registeredClientId", auth.getRegisteredClientId());
        map.put("principalName", auth.getPrincipalName());
        map.put("authorizationGrantType", auth.getAuthorizationGrantType().getValue());
        map.put("authorizedScopes", auth.getAuthorizedScopes());
        map.put("attributes", auth.getAttributes());
        map.put("accessToken", serializeAccessToken(unwrap(auth.getAccessToken())));
        map.put("accessTokenMetadata", serializeTokenMetadata(auth.getAccessToken()));
        map.put("refreshToken", serializeRefreshToken(unwrap(auth.getRefreshToken())));
        map.put("refreshTokenMetadata", serializeTokenMetadata(auth.getRefreshToken()));
        map.put("idToken", serializeOidcIdToken(unwrap(auth.getToken(OidcIdToken.class))));
        map.put("idTokenMetadata", serializeTokenMetadata(auth.getToken(OidcIdToken.class)));
        map.put("authorizationCode", serializeAuthorizationCode(unwrap(auth.getToken(OAuth2AuthorizationCode.class))));
        map.put("authorizationCodeMetadata", serializeTokenMetadata(auth.getToken(OAuth2AuthorizationCode.class)));
        map.put("deviceCode", serializeDeviceCode(unwrap(auth.getToken(OAuth2DeviceCode.class))));
        map.put("deviceCodeMetadata", serializeTokenMetadata(auth.getToken(OAuth2DeviceCode.class)));
        map.put("userCode", serializeUserCode(unwrap(auth.getToken(OAuth2UserCode.class))));
        map.put("userCodeMetadata", serializeTokenMetadata(auth.getToken(OAuth2UserCode.class)));
        return map;
    }

    @SuppressWarnings("unchecked")
    private OAuth2Authorization deserialize(String json) {
        if (!StringUtils.hasText(json)) return null;
        try {
            Map<String, Object> map = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
            String realRegisteredClientId = (String) map.get("registeredClientId");
            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(
                    stubClient(realRegisteredClientId)
            );
            // 关键: 必须恢复原始 ID, 否则 build() 会生成新 UUID,
            // 导致 remove()/findByToken() 按 ID 操作时找不到 Redis 中的正确记录
            builder.id((String) map.get("id"));
            builder.principalName((String) map.get("principalName"));
            builder.authorizationGrantType(new AuthorizationGrantType(
                    (String) map.get("authorizationGrantType")));

            builder.authorizedScopes(toSet(map.get("authorizedScopes")));

            Map<String, Object> attributes = (Map<String, Object>) map.getOrDefault("attributes", new HashMap<>());
            for (Map.Entry<String, Object> e : attributes.entrySet()) {
                Object value = e.getValue();
                value = convertAttribute(e.getKey(), value);
                if (value != null) {
                    builder.attribute(e.getKey(), value);
                }
            }

            Object atRaw = map.get("accessToken");
            if (atRaw != null) {
                OAuth2AccessToken at = deserializeAccessToken((Map<String, Object>) atRaw);
                Map<String, Object> atMeta = (Map<String, Object>) map.getOrDefault("accessTokenMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(atMeta);
                builder.token(at, metadata -> metadata.putAll(atMeta));
            }

            Object rtRaw = map.get("refreshToken");
            if (rtRaw != null) {
                OAuth2RefreshToken rt = deserializeRefreshToken((Map<String, Object>) rtRaw);
                Map<String, Object> rtMeta = (Map<String, Object>) map.getOrDefault("refreshTokenMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(rtMeta);
                builder.token(rt, metadata -> metadata.putAll(rtMeta));
            }

            Object idtRaw = map.get("idToken");
            if (idtRaw != null) {
                OidcIdToken idt = deserializeOidcIdToken((Map<String, Object>) idtRaw);
                Map<String, Object> idtMeta = (Map<String, Object>) map.getOrDefault("idTokenMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(idtMeta);
                builder.token(idt, metadata -> metadata.putAll(idtMeta));
            }

            if (map.get("authorizationCode") != null) {
                OAuth2AuthorizationCode code = deserializeAuthorizationCode((Map<String, Object>) map.get("authorizationCode"));
                Map<String, Object> codeMeta = (Map<String, Object>) map.getOrDefault("authorizationCodeMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(codeMeta);
                builder.token(code, metadata -> metadata.putAll(codeMeta));
            }
            if (map.get("deviceCode") != null) {
                OAuth2DeviceCode dc = deserializeDeviceCode((Map<String, Object>) map.get("deviceCode"));
                Map<String, Object> dcMeta = (Map<String, Object>) map.getOrDefault("deviceCodeMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(dcMeta);
                builder.token(dc, metadata -> metadata.putAll(dcMeta));
            }
            if (map.get("userCode") != null) {
                OAuth2UserCode uc = deserializeUserCode((Map<String, Object>) map.get("userCode"));
                Map<String, Object> ucMeta = (Map<String, Object>) map.getOrDefault("userCodeMetadata", new HashMap<>());
                restoreTimeClaimsInMetadata(ucMeta);
                builder.token(uc, metadata -> metadata.putAll(ucMeta));
            }

            OAuth2Authorization result = builder.build();
            return result;
        } catch (Exception e) {
            log.error("反序列化 OAuth2Authorization 失败", e);
            return null;
        }
    }

    private RegisteredClient stubClient(String registeredClientId) {
        return RegisteredClient
                .withId(registeredClientId)
                .clientId("stub")
                .clientAuthenticationMethod(
                        ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8080/callback")
                .scope("openid")
                .build();
    }

    private static final Set<String> SKIP_ATTRIBUTES = Set.of(
            Principal.class.getName(),
            Authentication.class.getName()
    );

    private Object convertAttribute(String key, Object value) {
        if (value == null) return null;
        // JSON 反序列化后 Set 变成 ArrayList, SAS 的 OAuth2DeviceVerificationAuthenticationProvider
        // 期望 attributes 中的 scope 是 Set<String>, 需转回 Set 避免 ClassCastException
        if (OAuth2ParameterNames.SCOPE.equals(key)) {
            return toSet(value);
        }
        if (SKIP_ATTRIBUTES.contains(key)) {
            if (value instanceof Map m) {
                Object name = m.get("name");
                if (name != null) {
                    return new UsernamePasswordAuthenticationToken(name, null,
                            List.of(new SimpleGrantedAuthority("ROLE_USER")));
                }
            }
            return null;
        }
        if (!(value instanceof Map linkedMap)) return value;
        try {
            Class<?> clazz = Class.forName(key);
            if (clazz.isInterface()) return null;
            return objectMapper.copy()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .convertValue(linkedMap, clazz);
        } catch (ClassNotFoundException e) {
            return value;
        } catch (Exception e) {
            log.debug("跳过无法转换的 attribute {}: {}", key, e.getMessage());
            return value;
        }
    }

    // ------------------------------------------------------------------
    // 各种 Token 的序列化/反序列化 (SAS 1.4.1: 构造函数, 无 Builder)
    // ------------------------------------------------------------------

    /**
     * 序列化 Token 的 metadata (含 invalidated 标志等)。
     * SAS 标准 /oauth2/revoke 会标记 token 为 invalidated=true 并调 save()，
     * 若不持久化此标志，反序列化后 token 会"复活"。
     */
    private Map<String, Object> serializeTokenMetadata(OAuth2Authorization.Token<?> tokenWrapper) {
        if (tokenWrapper == null) return null;
        Map<String, Object> meta = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : tokenWrapper.getMetadata().entrySet()) {
            Object v = e.getValue();
            if (v == null) continue;
            if (v instanceof Map) {
                // metadata 中的 claims Map 可能含 Instant 类型的 exp/iat 等,
                // 需转为 epoch 秒避免 Jackson WRITE_DATES_AS_TIMESTAMPS=false 导致类型丢失
                @SuppressWarnings("unchecked")
                Map<String, Object> mapVal = (Map<String, Object>) v;
                Map<String, Object> converted = new LinkedHashMap<>();
                for (Map.Entry<String, Object> me : mapVal.entrySet()) {
                    if (me.getValue() instanceof Instant instant) {
                        converted.put(me.getKey(), instant.getEpochSecond());
                    } else {
                        converted.put(me.getKey(), me.getValue());
                    }
                }
                meta.put(e.getKey(), converted);
            } else if (v instanceof Serializable || v instanceof List) {
                meta.put(e.getKey(), v);
            }
        }
        return meta;
    }

    /**
     * 将 metadata 中嵌套 Map 里的时间类型 claim 从 String/Number 恢复为 Instant.
     * 兼容修复前序列化的旧数据 (Instant 被 Jackson 序列化为 ISO 字符串).
     */
    @SuppressWarnings("unchecked")
    private void restoreTimeClaimsInMetadata(Map<String, Object> meta) {
        if (meta == null) return;
        for (Object value : meta.values()) {
            if (!(value instanceof Map)) continue;
            Map<String, Object> mapVal = (Map<String, Object>) value;
            for (String key : TIME_CLAIMS) {
                Object v = mapVal.get(key);
                if (v instanceof Instant) continue;
                if (v instanceof String s) {
                    try {
                        mapVal.put(key, Instant.parse(s));
                    } catch (Exception ignored) {
                        try { mapVal.put(key, Instant.ofEpochSecond(Long.parseLong(s))); } catch (Exception ignored2) {}
                    }
                } else if (v instanceof Number n) {
                    mapVal.put(key, Instant.ofEpochSecond(n.longValue()));
                }
            }
        }
    }

    private Map<String, Object> serializeAccessToken(OAuth2AccessToken token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("tokenType", token.getTokenType().getValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        m.put("scopes", token.getScopes());
        return m;
    }

    private OAuth2AccessToken deserializeAccessToken(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        Set<String> scopes = toSet(m.get("scopes"));
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                m.get("value").toString(), issuedAt, expiresAt, scopes);
    }

    private Map<String, Object> serializeRefreshToken(OAuth2RefreshToken token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        return m;
    }

    private OAuth2RefreshToken deserializeRefreshToken(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        return new OAuth2RefreshToken(m.get("value").toString(), issuedAt, expiresAt);
    }

    // OidcIdToken 必须持久化: 刷新 token 时 JwtGenerator 会读取已存储的 idToken 复制 claims,
    // 缺失会导致 NPE (JwtGenerator.java:144); userinfo 端点也依赖它校验 access_token
    // 注意: claims 中的 exp/iat 是 Instant 类型, Jackson 配置 WRITE_DATES_AS_TIMESTAMPS=false
    // 会将 Instant 序列化为 ISO 字符串, 反序列化为 Map<String,Object> 时变成 String,
    // 导致 OidcUserInfoEndpointFilter 强制 (Instant) 转换失败. 这里手动转 epoch 秒规避.
    /** 需要特殊处理时间类型转换的 OIDC claim 名称集合 */
    private static final Set<String> TIME_CLAIMS = Set.of("exp", "iat", "nbf", "auth_time", "updated_at");

    private Map<String, Object> serializeOidcIdToken(OidcIdToken token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        // 将 claims 中的 Instant 转为 epoch 秒, 避免 Jackson 序列化为 ISO 字符串后类型丢失
        Map<String, Object> convertedClaims = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : token.getClaims().entrySet()) {
            if (e.getValue() instanceof Instant instant) {
                convertedClaims.put(e.getKey(), instant.getEpochSecond());
            } else {
                convertedClaims.put(e.getKey(), e.getValue());
            }
        }
        m.put("claims", convertedClaims);
        return m;
    }

    @SuppressWarnings("unchecked")
    private OidcIdToken deserializeOidcIdToken(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        Map<String, Object> claims = new LinkedHashMap<>(
                (Map<String, Object>) m.getOrDefault("claims", new HashMap<>()));
        // 将时间类型的 claim 从 String/Number 转回 Instant (兼容旧数据)
        for (String key : TIME_CLAIMS) {
            Object v = claims.get(key);
            if (v instanceof Instant) continue;
            if (v instanceof String s) {
                try {
                    claims.put(key, Instant.parse(s));
                } catch (Exception ignored) {
                    try { claims.put(key, Instant.ofEpochSecond(Long.parseLong(s))); } catch (Exception ignored2) {}
                }
            } else if (v instanceof Number n) {
                claims.put(key, Instant.ofEpochSecond(n.longValue()));
            }
        }
        return new OidcIdToken(m.get("value").toString(), issuedAt, expiresAt, claims);
    }

    private Map<String, Object> serializeAuthorizationCode(OAuth2AuthorizationCode token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        return m;
    }

    private OAuth2AuthorizationCode deserializeAuthorizationCode(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        return new OAuth2AuthorizationCode(m.get("value").toString(), issuedAt, expiresAt);
    }

    private Map<String, Object> serializeDeviceCode(OAuth2DeviceCode token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        return m;
    }

    private OAuth2DeviceCode deserializeDeviceCode(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        return new OAuth2DeviceCode(m.get("value").toString(), issuedAt, expiresAt);
    }

    private Map<String, Object> serializeUserCode(OAuth2UserCode token) {
        if (token == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("value", token.getTokenValue());
        m.put("issuedAt", token.getIssuedAt() != null ? token.getIssuedAt().toString() : null);
        m.put("expiresAt", token.getExpiresAt() != null ? token.getExpiresAt().toString() : null);
        return m;
    }

    private OAuth2UserCode deserializeUserCode(Map<String, Object> m) {
        Instant issuedAt = m.get("issuedAt") != null ? Instant.parse(m.get("issuedAt").toString()) : null;
        Instant expiresAt = m.get("expiresAt") != null ? Instant.parse(m.get("expiresAt").toString()) : null;
        return new OAuth2UserCode(m.get("value").toString(), issuedAt, expiresAt);
    }

    // ------------------------------------------------------------------
    // TTL 计算
    // ------------------------------------------------------------------

    private Duration computeTtl(OAuth2Authorization auth) {
        Duration ttl = Duration.ofHours(1);
        OAuth2RefreshToken rt = unwrap(auth.getRefreshToken());
        if (rt != null && rt.getExpiresAt() != null) {
            ttl = Duration.between(Instant.now(), rt.getExpiresAt());
        } else {
            OAuth2AccessToken at = unwrap(auth.getAccessToken());
            if (at != null && at.getExpiresAt() != null) {
                ttl = Duration.between(Instant.now(), at.getExpiresAt());
            }
        }
        return ttl.isNegative() ? Duration.ofSeconds(1) : ttl;
    }

    private Duration computeTtlForToken(Instant expiresAt) {
        if (expiresAt == null) return Duration.ofHours(1);
        Duration d = Duration.between(Instant.now(), expiresAt);
        return d.isNegative() ? Duration.ofSeconds(1) : d;
    }

    @SuppressWarnings("unchecked")
    private Set<String> toSet(Object value) {
        if (value == null) return Collections.emptySet();
        if (value instanceof Set) return (Set<String>) value;
        if (value instanceof List) return new HashSet<>((List<String>) value);
        return Collections.singleton(value.toString());
    }
}
