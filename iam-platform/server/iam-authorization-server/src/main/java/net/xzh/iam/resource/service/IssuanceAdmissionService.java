package net.xzh.iam.resource.service;

import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 签发准入服务 — 混合登录隔离 (门户/管理端用户不跨端登录).
 * <p>
 * 在授权端点 (/oauth2/authorize) 签发授权码之前判定「该用户能否登录该客户端」, 与令牌自省层的
 * 双维交集读<b>同一套 scope 字典</b>、用<b>同一条语义</b> (用户 RBAC 码 ∩ 客户端 scope 展开码),
 * 不新建任何规则表、不复活已退役的 iam_client_policy:
 * <ul>
 *   <li>客户端 scope 展开非空且与用户码交集为空 → 拒绝签发 (fail-closed), 如 PORTAL 用户登 admin-app;</li>
 *   <li>客户端 scope 展开为 0 码 (纯 OIDC 客户端, 如 web-app/device-app/mobile-app) → 放行,
 *       其令牌在自省层同样拿不到任何业务码 (仅能访问 OIDC 标准端点), 不参与业务权限模型, 不闸;</li>
 *   <li>客户端/用户缺失 → 拒绝 (fail-closed)。</li>
 * </ul>
 * 决策在服务端授权服务器做出并记录审计日志, 符合「授权决策须服务端、可归因、可追溯」原则。
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IssuanceAdmissionService {

    private final ScopeService scopeService;
    private final PermissionService permissionService;

    /**
     * 判定用户能否登录 (获发授权码给) 指定客户端.
     *
     * @param clientId 客户端 client_id (授权请求参数)
     * @param userCode 业务用户编码 (令牌 sub, 即授权会话 principal name)
     * @return true=放行签发; false=拒绝 (fail-closed)
     */
    public boolean allowLogin(String clientId, String userCode) {
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(userCode)) {
            return false;
        }
        Set<String> scopeCodes = scopeService.resolveClientBusinessCodes(clientId);
        if (scopeCodes.isEmpty()) {
            // 逃逸阀: 纯 OIDC 客户端 (scope 展开无业务码), 不参与业务权限模型, 不闸。
            // 其令牌在自省层同样交集为空、一码不放, 仅能访问 OIDC 标准端点 (/userinfo 等)。
            log.debug("[Issuance] 纯 OIDC 客户端 (无业务 scope) 放行, client={}, user={}", clientId, userCode);
            return true;
        }
        Set<String> userCodes = permissionService.findPermissions(userCode);
        boolean allowed = userCodes.stream().anyMatch(scopeCodes::contains);
        log.debug("[Issuance] 签发准入裁决, client={}, user={}, scopeCodes={}, userCodes={}, allowed={}",
                clientId, userCode, scopeCodes, userCodes, allowed);
        return allowed;
    }
}
