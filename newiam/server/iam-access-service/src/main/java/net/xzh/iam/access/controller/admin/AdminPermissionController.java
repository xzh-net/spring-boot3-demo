package net.xzh.iam.access.controller.admin;

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
import net.xzh.iam.access.entity.SysPermission;
import net.xzh.iam.access.service.RbacService;

/**
 * 权限管理 API（资源中心管理端能力域）.
 * <p>仅面向管理后台（iam-admin-service），路径由?/api/admin/** 规则保护: Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/permissions")
@RequiredArgsConstructor
public class AdminPermissionController {

    private final RbacService rbacService;

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
}