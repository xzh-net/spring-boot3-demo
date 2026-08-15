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
 * 内部角色供给接口（资源中心服务间内部能力域）.
 * <p>
 * 仅供认证中心（iam-authorization-server）M2M 调用，用于登录时注入 id_token claims
 * 与令牌签发准入判定；不属于对外三分类（管理端 / portal 端 / 公开端）。
 * <p>
 * 安全约束 (D6): 本路径由 {@code hasRole('SERVICE')} 把关, 仅允许
 * client_credentials 服务 token 访问; 返回值<b>只含角色与权限编码, 不含任何凭据</b>.
 * <p>
 * 标识: 路径参数为业务用户编码 user_code (token sub), 用户权威在认证中心 (V6.2 已无影子用户表)。
 */
@Slf4j
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalRoleController {

    private final PermissionService permissionService;

    /**
     * 按业务用户编码返回角色/权限编码集合.
     * <p>响应: {@code {userCode, roles: ["ROLE_ADMIN"], permissions: ["app:portal", ...]}}
     */
    @GetMapping("/user/{userCode}/roles")
    public Result<Map<String, Object>> roles(@PathVariable String userCode) {
        Set<String> roles = new LinkedHashSet<>();
        for (String code : permissionService.findRoleCodes(userCode)) {
            roles.add(code.startsWith("ROLE_") ? code : "ROLE_" + code);
        }
        List<String> permissions = permissionService.findPermissions(userCode)
                .stream().sorted().toList();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("userCode", userCode);
        data.put("roles", roles);
        data.put("permissions", permissions);
        return Result.ok(data);
    }
}