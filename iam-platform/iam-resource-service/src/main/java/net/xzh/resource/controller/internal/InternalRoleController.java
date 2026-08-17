package net.xzh.resource.controller.internal;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.service.PermissionService;

/**
 * 内部角色供给接口（资源中心服务间内部能力域, 对标认证中心内省接口 / 角色内省）.
 * <p>
 * 仅供认证中心（iam-authorization-server）M2M 调用，用于登录时注入 id_token claims
 * 与令牌签发准入判定；不属于对外三分类（管理端 / portal 端 / 公开端）。
 * <p>
 * 安全约束 (D6): 本路径为<b>硬规则</b> (仅认证中心 M2M 可调): 由
 * {@code PORTAL_SERVICE_TOKEN} + client_id = {@code resource-server} 双重把关,
 * 裁决在 {@code EndpointAdmissionManager} 前置分支, 不进入 iam_endpoint_policy 规则表;
 * 返回值<b>只含角色与权限编码, 不含任何凭据</b>.
 * <p>
 * 标识: 路径参数为业务用户编码 user_code (token sub), 用户权威在认证中心 (V6.2 已无影子用户表)。
 * <p>
 * 边界: controller/internal 仅承载<b>只读内省</b> (对标 /oauth2/introspect); 管理写操作
 * (如删除用户联动清理) 归 controller/admin 管理端能力, 以管理 M2M 服务凭证把关, 见
 * {@link net.xzh.resource.controller.admin.AdminUserDataController}。
 */
@Slf4j
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalRoleController {

    private final PermissionService permissionService;

    /**
     * 按业务用户编码返回角色/权限编码集合.
     * <p>响应: {@code {userCode, roles: ["ADMIN"], permissions: ["app:portal", ...]}}
     * (业务角色编码原样返回, 不再拼 ROLE_ 前缀; 令牌类别由各端内省/签发统一判定)
     */
    @GetMapping("/user/{userCode}/roles")
    public Result<Map<String, Object>> roles(@PathVariable String userCode) {
        Set<String> roles = new LinkedHashSet<>(permissionService.findRoleCodes(userCode));
        List<String> permissions = permissionService.findPermissions(userCode)
                .stream().sorted().toList();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("userCode", userCode);
        data.put("roles", roles);
        data.put("permissions", permissions);
        return Result.ok(data);
    }
}