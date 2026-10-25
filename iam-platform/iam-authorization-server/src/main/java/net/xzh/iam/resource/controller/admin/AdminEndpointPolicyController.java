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
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import net.xzh.iam.resource.service.EndpointPolicyService;

/**
 * 资源接口准入策略管理 API (资源中心管理端能力域).
 * <p>仅面向管理后台 (iam-admin-bff), 路径由 /api/admin/** 规则保护: Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证.</p>
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/endpoint-policies")
@RequiredArgsConstructor
public class AdminEndpointPolicyController {

    private final EndpointPolicyService endpointPolicyService;

    @GetMapping
    public Result<List<IamEndpointPolicy>> list() {
        return Result.ok(endpointPolicyService.listEndpointPolicies());
    }

    @PostMapping
    public Result<Void> create(@RequestBody IamEndpointPolicy policy) {
        endpointPolicyService.createEndpointPolicy(policy);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody IamEndpointPolicy policy) {
        endpointPolicyService.updateEndpointPolicy(id, policy);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        endpointPolicyService.deleteEndpointPolicy(id);
        return Result.ok();
    }
}
