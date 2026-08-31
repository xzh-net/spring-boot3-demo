package net.xzh.iam.auth.security;

import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.remote.AccessDecisionClient;

/**
 * 客户端登录边界准入 (干净切割后的薄委托层).
 * <p>
 * 本类不再持有任何策略数据与评估逻辑: 规则 (client_policy) 与事实 (RBAC 角色) 都在
 * 权限中心 iam-access-service, 本类仅把"该用户能否登录该客户端"的问询转发给
 * {@link AccessDecisionClient#decide} (SWR 缓存), 并把不放行结果转换为
 * OAuth2 access_denied 拒绝。权限中心不可达且缓存超出 max-stale 时同样 fail-closed 拒绝。
 * <p>
 * 签发侧准入语义与旧版一致: 发码阶段与令牌签发阶段共用, 拒绝时不产生任何令牌与授权记录。
 */
@Slf4j
@Component
public final class ClientUserPolicyService {

    /** RFC 6749 Section 5.2 — 令牌端点错误文档 URI */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final AccessDecisionClient accessDecisionClient;

    public ClientUserPolicyService(AccessDecisionClient accessDecisionClient) {
        this.accessDecisionClient = accessDecisionClient;
    }

    /**
     * 校验指定客户端是否允许该用户获取令牌, 不通过时抛出
     * {@link OAuth2AuthenticationException}(access_denied)。
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
        AccessDecisionClient.DecideResult result;
        try {
            result = accessDecisionClient.decide(username, clientId);
        } catch (Exception e) {
            // fail-closed: 无法取得判定 (含缓存耗尽) 一律拒绝, 无猜测成分
            log.warn("[令牌准入] 准入决策不可用, fail-closed 拒绝 client={}, user={}: {}",
                    clientId, username, e.getMessage());
            deny(clientId, username, null);
            return;
        }
        if (!result.allowed()) {
            deny(clientId, username, result.roles());
        }
    }

    private void deny(String clientId, String username, Set<String> userRoles) {
        log.info("[令牌准入] 拒绝签发: 客户端={}, 用户={}, 用户角色={}", clientId, username, userRoles);
        throw new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.ACCESS_DENIED,
                "当前用户不允许在该客户端登录",
                ERROR_URI));
    }
}
