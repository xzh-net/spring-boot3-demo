package net.xzh.resource.controller.admin;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.service.RbacService;

/**
 * 用户-角色绑定 API（资源中心管理端能力域）.
 * <p>仅面向管理后台（iam-admin-service），路径由 /api/admin/** 规则保护: Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证。
 * <p>V6.2: 用户标识 username 改为业务用户编码 user_code (token sub), 影子用户表已删除。
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/user-roles")
@RequiredArgsConstructor
public class AdminUserRoleController {

    private final RbacService rbacService;

    /**
     * 查询某业务用户编码 (user_code) 已绑定的角色 ID 列表.
     */
    @GetMapping("/{userCode}")
    public Result<Map<String, Object>> listOfUser(@PathVariable String userCode) {
        return Result.ok(Map.of(
                "userCode", userCode,
                "roleIds", rbacService.listRoleIdsOfUser(userCode)));
    }

    /**
     * 保存某用户的角色绑定 (整体覆盖, 按 user_code).
     */
    @PutMapping("/{userCode}")
    public Result<Void> assign(@PathVariable String userCode, @RequestBody List<Long> roleIds) {
        rbacService.assignRolesToUser(userCode, roleIds);
        return Result.ok();
    }
}