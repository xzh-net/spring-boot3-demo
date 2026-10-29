package net.xzh.iam.resource.controller.admin;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import net.xzh.iam.resource.service.EndpointPolicyService;

/**
 * 资源接口准入策略查询 API (<b>只读</b>).
 * <p>
 * 本表唯一写入方=启动自扫描补缺 (EndpointPolicyScanInitializer); 精确权限码权威=iam.sql 种子,
 * 扫描不回写 authority。管理端无新增/编辑/删除入口 (页面同步只读), 端点准入由代码与种子维护。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/admin/endpoint-policies")
@RequiredArgsConstructor
public class AdminEndpointPolicyController {

    private final EndpointPolicyService endpointPolicyService;

    @GetMapping
    public Result<List<IamEndpointPolicy>> list() {
        return Result.ok(endpointPolicyService.listEndpointPolicies());
    }
}
