package net.xzh.iam.resource.controller.admin;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.xzh.iam.common.Result;
import net.xzh.iam.resource.service.ScopeService;
import net.xzh.iam.resource.vo.ScopeVO;

/**
 * 三域管理 API — 授权范围域 (/api/admin/scopes), <b>只读</b>.
 * <p>
 * sys_scope / sys_scope_permission 为只读字典 (SQL 种子演进), 本控制器不提供
 * 增删改方法; 客户端↔scope 绑定的编辑走客户端管理 (/api/admin/clients 的 scopes)。
 * 经 Order(2) 安全链保护 (Bearer + ADMIN_SERVICE_TOKEN)。
 * </p>
 */
@RestController
@RequestMapping("/api/admin/scopes")
@RequiredArgsConstructor
public class AdminScopeController {

    private final ScopeService scopeService;

    /** 授权范围列表 (含内含权限码与引用客户端) */
    @GetMapping
    public Result<List<ScopeVO>> list() {
        return Result.ok(scopeService.listScopes());
    }
}
