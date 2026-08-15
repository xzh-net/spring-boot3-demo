package net.xzh.resource.controller.admin;

import java.util.List;
import java.util.Map;

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
import net.xzh.resource.common.Result;
import net.xzh.resource.entity.SysRole;
import net.xzh.resource.service.RbacService;

/**
 * 角色管理 API（资源中心管理端能力域）.
 * <p>仅面向管理后台（iam-admin-service），路径由 /api/admin/** 规则保护: Bearer + hasRole('ADMIN').
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/roles")
@RequiredArgsConstructor
public class AdminRoleController {

    private final RbacService rbacService;

    @GetMapping
    public Result<List<Map<String, Object>>> list() {
        return Result.ok(rbacService.listRoles());
    }

    @PostMapping
    public Result<Void> create(@RequestBody SysRole role) {
        rbacService.createRole(role);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody SysRole role) {
        rbacService.updateRole(id, role);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        rbacService.deleteRole(id);
        return Result.ok();
    }
}