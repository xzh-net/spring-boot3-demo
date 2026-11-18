package net.xzh.iam.resource.controller.admin;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.xzh.iam.common.Result;
import net.xzh.iam.resource.entity.ClientLoginPolicy;
import net.xzh.iam.resource.service.LoginAdmissionService;

/**
 * 三域管理 API — 登录准入域 (/admin/login-policies).
 * <p>
 * 登录维度 (client × 主体 allow-list) 的管理端读写入口, 页面 login_policy.html 使用。
 * 与授权维度正交: 本域只管「谁能登录该客户端」, 不影响自省层业务码交集。
 * <p>
 * 权限码复用客户端域 (client:read / client:write): 登录准入即客户端配置的一部分,
 * 不新增权限码 (避免连改 sys_permission / sys_role_permission / sys_scope_permission 四处种子)。
 * 经 Order(3) 资源链 + iam_endpoint 端点准入保护。
 * </p>
 */
@RestController
@RequestMapping("/admin/login-policies")
@RequiredArgsConstructor
public class AdminLoginPolicyController {

    private final LoginAdmissionService loginAdmissionService;

    /** 全量准入行 (页面按 client_id 合并 /admin/clients 展示) */
    @GetMapping
    public Result<List<ClientLoginPolicy>> list() {
        return Result.ok(loginAdmissionService.listAll());
    }

    /** 某客户端的准入行 */
    @GetMapping("/{clientId}")
    public Result<List<ClientLoginPolicy>> listByClient(@PathVariable String clientId) {
        return Result.ok(loginAdmissionService.listAll().stream()
                .filter(r -> clientId.equals(r.getClientId()))
                .toList());
    }

    /** 整体覆盖某客户端的准入行 (空数组 = 清空 = 该客户端拒绝所有登录) */
    @PutMapping("/{clientId}")
    public Result<Void> replace(@PathVariable String clientId,
                                @RequestBody List<ClientLoginPolicy> rows) {
        loginAdmissionService.replacePolicies(clientId, rows);
        return Result.ok();
    }
}
