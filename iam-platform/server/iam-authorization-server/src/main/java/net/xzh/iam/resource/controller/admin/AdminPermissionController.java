package net.xzh.iam.resource.controller.admin;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import net.xzh.iam.resource.entity.SysPermission;
import net.xzh.iam.resource.service.RbacService;
import net.xzh.iam.resource.service.ScopeService;

/**
 * 权限管理 API（资源中心管理端能力域）.
 * <p>仅面向管理后台（iam-admin-bff），路径由?/api/admin/** 规则保护: Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证.
 * <p>2026-11-18 (Q1A/Q2A): 「所属授权范围」映射行维护入口 (sys_scope_permission, permission:write) —
 * 组定义 sys_scope 仍走种子, 映射保存即时生效 (内省实时展开)。</p>
 */
@Slf4j
@RestController
@RequestMapping("/admin/permissions")
@RequiredArgsConstructor
public class AdminPermissionController {

    private final RbacService rbacService;
    private final ScopeService scopeService;

    @GetMapping
    public Result<List<SysPermission>> list() {
        return Result.ok(rbacService.listPermissions());
    }

    @PostMapping
    public Result<Void> create(@RequestBody SysPermission permission) {
        rbacService.createPermission(permission);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody SysPermission permission) {
        rbacService.updatePermission(id, permission);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        rbacService.deletePermission(id);
        return Result.ok();
    }

    /** 把权限码加入授权范围组 (映射行维护, 幂等; 保存即时生效) */
    @PostMapping("/{id}/scopes/{scopeId}")
    public Result<Void> addScope(@PathVariable Long id, @PathVariable Long scopeId) {
        scopeService.addPermissionToScope(scopeId, id);
        return Result.ok();
    }

    /** 把权限码移出授权范围组 (持有该组的客户端立即失去该码) */
    @DeleteMapping("/{id}/scopes/{scopeId}")
    public Result<Void> removeScope(@PathVariable Long id, @PathVariable Long scopeId) {
        scopeService.removePermissionFromScope(scopeId, id);
        return Result.ok();
    }
}