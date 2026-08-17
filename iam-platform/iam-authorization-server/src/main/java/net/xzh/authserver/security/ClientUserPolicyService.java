package net.xzh.authserver.security;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.ClientPolicy;
import net.xzh.authserver.mapper.ClientPolicyMapper;
import net.xzh.authserver.remote.RemoteRoleService;

/**
 * 客户端登录边界策略 (登录边界隔离): client_id → 允许登录的角色集合.
 * <p>
 * 管理端用户与门户端用户统一在 {@code iam_identity.sys_user} 中一并管理, 为隔离两类
 * 人群交叉登录 (管理账号误入门户端 / 门户账号误入管理端), 以本表控制"允许谁以该客户端
 * 身份登录"。该策略在令牌签发/授权码发放前先行校验, 不通过即拒绝登录。
 * 策略配置自 yaml (client-identity-policy) 迁移至表 {@code iam_client_policy}
 * (改造清单: 系统准入配置从 yaml 转换成表), 角色权威在资源中心 RBAC:
 * <ul>
 *   <li>表内无该客户端策略行 → 默认放行 (不限制);</li>
 *   <li>策略行 allowed_roles 为空或 {@code *} → 放行全部;</li>
 *   <li>否则以用户业务角色 (资源中心 D6 接口) 与允许集合做交集, 交集非空才放行;</li>
 *   <li>角色解析失败 (资源中心不可达) 且配置了策略 → 无法证明允许, 拒绝签发 (fail-closed)。</li>
 * </ul>
 */
@Slf4j
@Component
public final class ClientUserPolicyService {

    /** RFC 6749 Section 5.2 — 令牌端点错误文档 URI */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final ClientPolicyMapper clientPolicyMapper;
    private final RemoteRoleService remoteRoleService;

    public ClientUserPolicyService(ClientPolicyMapper clientPolicyMapper, RemoteRoleService remoteRoleService) {
        this.clientPolicyMapper = clientPolicyMapper;
        this.remoteRoleService = remoteRoleService;
    }

    /**
     * 校验指定客户端是否允许该用户获取令牌。
     * <p>
     * 不通过时抛出 {@link OAuth2AuthenticationException}(access_denied)，调用方
     * 应在令牌生成/持久化之前调用，保证拒绝时不产生任何令牌与授权记录。
     *
     * @param client   目标客户端 (取自已认证的客户端主体)
     * @param username 资源所有者用户名
     */
    public void check(RegisteredClient client, String username) {
        check(client == null ? null : client.getClientId(), username);
    }

    /**
     * 按 {@code clientId} 校验是否允许该用户获取令牌 (发码阶段与签发阶段共用)。
     */
    public void check(String clientId, String username) {
        if (clientId == null || clientId.isBlank() || username == null || username.isBlank()) {
            return;
        }
        Set<String> allowed = resolveAllowedRoles(clientId);
        // 未配置策略 / 配置为不限制 → 放行
        if (allowed == null || allowed.isEmpty()) {
            return;
        }
        Set<String> userRoles;
        try {
            userRoles = remoteRoleService.getUserRoles(username);
        } catch (Exception e) {
            log.warn("[令牌准入] 解析用户角色失败 client={}, user={}: {}", clientId, username, e.getMessage());
            deny(clientId, username, null);
            return;
        }
        Set<String> normalizedRoles = userRoles.stream()
                .map(ClientUserPolicyService::normalizeRole)
                .collect(Collectors.toSet());
        boolean allowedFlag = normalizedRoles.stream().anyMatch(allowed::contains);
        if (!allowedFlag) {
            deny(clientId, username, normalizedRoles);
        }
    }

    /**
     * 解析客户端允许的角色编码集合.
     *
     * @return null=未配置策略(放行); 空集合=放行全部; 否则为允许的角色编码集合 (已规范化)
     */
    private Set<String> resolveAllowedRoles(String clientId) {
        ClientPolicy policy = clientPolicyMapper.selectOne(
                new QueryWrapper<ClientPolicy>().eq("client_id", clientId));
        if (policy == null || !Boolean.TRUE.equals(policy.getStatus())) {
            return null;
        }
        String raw = policy.getAllowedRoles() == null ? "" : policy.getAllowedRoles().trim();
        if (raw.isBlank() || "*".equals(raw)) {
            return new LinkedHashSet<>();
        }
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(ClientUserPolicyService::normalizeRole)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static String normalizeRole(String role) {
        String r = role == null ? "" : role.trim();
        return r.toUpperCase(Locale.ROOT).startsWith("ROLE_") ? r.substring(5) : r;
    }

    private void deny(String clientId, String username, Set<String> userRoles) {
        log.info("[令牌准入] 拒绝签发: 客户端={}, 用户={}, 用户角色={}",
                clientId, username, userRoles);
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.ACCESS_DENIED,
                "当前用户不允许在该客户端登录",
                ERROR_URI));
    }
}