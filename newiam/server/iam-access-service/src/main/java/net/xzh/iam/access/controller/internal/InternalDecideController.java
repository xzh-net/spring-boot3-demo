package net.xzh.iam.access.controller.internal;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.access.entity.ClientPolicy;
import net.xzh.iam.access.mapper.ClientPolicyMapper;
import net.xzh.iam.access.service.PermissionService;
import net.xzh.iam.access.vo.DecideVO;
import net.xzh.iam.common.Result;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

/**
 * 登录准入统一决策接口 (PDP 问询端点, internal 硬规则域).
 * <p>
 * 干净切割后认证中心登录链路的唯一裁决来源: 规则 (iam_client_policy) 与事实
 * (sys_user_role → sys_role) 都在本服务本地, 一次问询同时返回「是否放行」与
 * 「角色快照」, 取代旧版"拉全量角色回认证中心本地评估 + user_label 降级猜测"。
 * <p>
 * 请求经 EndpointAdmissionManager internal 域硬规则保护: 仅认证中心 M2M
 * (resource-server 服务令牌) 可调。
 * <p>
 * 裁决语义 (与旧版 ClientUserPolicyService 完全一致):
 * <ul>
 *   <li>clientId 为空 → 仅解析角色, 不做客户端准入闸门 (UserDetailsService 场景);</li>
 *   <li>无策略行 / 策略停用 → 放行;</li>
 *   <li>allowed_roles 为空或 * → 放行全部;</li>
 *   <li>否则与用户业务角色求交集 (角色编码规范化: 去 ROLE_ 前缀), 交集非空才放行。</li>
 * </ul>
 */
@Slf4j
@RestController
@RequestMapping("/api/internal/access")
@RequiredArgsConstructor
public class InternalDecideController {

    private final PermissionService permissionService;
    private final ClientPolicyMapper clientPolicyMapper;

    /**
     * 登录准入决策问询.
     *
     * @param req userCode 必填 (令牌 sub); clientId 可空 (空 = 仅解析角色)
     */
    @PostMapping("/decide")
    public Result<DecideVO> decide(@RequestBody DecideReq req) {
        if (req == null || req.userCode() == null || req.userCode().isBlank()) {
            throw new IllegalArgumentException("userCode 必填");
        }
        String userCode = req.userCode().trim();
        String clientId = (req.clientId() == null || req.clientId().isBlank()) ? null : req.clientId().trim();

        // 事实: 用户业务角色 (本地 RBAC)
        List<String> roles = permissionService.findRoleCodes(userCode);

        // 规则: 客户端登录边界策略 (本地 iam_client_policy)
        boolean allowed = true;
        if (clientId != null) {
            allowed = evaluate(clientId, roles);
        }

        DecideVO vo = new DecideVO();
        vo.setAllowed(allowed);
        vo.setRoles(roles);
        log.debug("[decide] user={}, client={} -> allowed={}, roles={}", userCode, clientId, allowed, roles);
        return Result.ok(vo);
    }

    /** 客户端准入闸门评估 (语义与旧版 ClientUserPolicyService 一致) */
    private boolean evaluate(String clientId, List<String> userRoles) {
        ClientPolicy policy = clientPolicyMapper.selectOne(
                new QueryWrapper<ClientPolicy>().eq("client_id", clientId));
        if (policy == null || !Boolean.TRUE.equals(policy.getStatus())) {
            return true;
        }
        String raw = policy.getAllowedRoles() == null ? "" : policy.getAllowedRoles().trim();
        if (raw.isBlank() || "*".equals(raw)) {
            return true;
        }
        Set<String> allowed = java.util.Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .map(InternalDecideController::normalizeRole)
                .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
        Set<String> normalized = userRoles.stream()
                .map(InternalDecideController::normalizeRole)
                .collect(Collectors.toSet());
        return normalized.stream().anyMatch(allowed::contains);
    }

    /** 角色编码规范化: 去 ROLE_ 前缀 (与旧版一致) */
    private static String normalizeRole(String role) {
        String r = role == null ? "" : role.trim();
        return r.toUpperCase(Locale.ROOT).startsWith("ROLE_") ? r.substring(5) : r;
    }

    /** decide 请求体 */
    public record DecideReq(String userCode, String clientId) {
    }
}
