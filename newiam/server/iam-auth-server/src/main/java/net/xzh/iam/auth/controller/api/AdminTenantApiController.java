package net.xzh.iam.auth.controller.api;

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
import net.xzh.iam.common.Result;
import net.xzh.iam.auth.entity.Tenant;
import net.xzh.iam.auth.service.TenantService;

/**
 * 三域管理 API — 租户域 (/api/internal/identity/tenants).
 * <p>
 * 认证中心「租户管理」面向 iam_identity.iam_tenant 的 REST 接口,
 * 经 Order(2) 安全链保护 (Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证), 供 admin-service / 管理前端调用。
 */
@RestController
@RequestMapping("/api/internal/identity/tenants")
@RequiredArgsConstructor
public class AdminTenantApiController {

    private final TenantService tenantService;

    @GetMapping
    public Result<List<Tenant>> list() {
        return Result.ok(tenantService.list());
    }

    @PostMapping
    public Result<Void> create(@RequestBody Tenant tenant) {
        tenantService.create(tenant);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody Tenant tenant) {
        tenantService.update(id, tenant);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        tenantService.delete(id);
        return Result.ok();
    }
}
