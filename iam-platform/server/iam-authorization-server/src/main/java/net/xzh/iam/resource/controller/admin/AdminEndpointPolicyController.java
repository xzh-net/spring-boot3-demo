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
 * 资源接口准入策略 API (<b>读写</b>).
 * <p>
 * 写入语义: 种子 (iam.sql) 一次性初始化 + 本 API 页面维护, <b>上线后以库数据为准</b> (种子不再执行,
 * 只存在增量变更或全量重置); 运行期规则每请求直查 DB, 写入即刻对全部实例生效。
 * 校验为轻量入参校验 (类型/权限存在性/唯一键由数据库兜底), 配置完整性属运维职责,
 * 启动仅打漂移告警不拦截。写操作按准入表受 policy:write 控制。
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

    /** 新增准入行 (方法+路径唯一, uk_endpoint 由数据库兜底) */
    @PostMapping
    public Result<IamEndpointPolicy> create(@RequestBody IamEndpointPolicy policy) {
        return Result.ok(endpointPolicyService.createPolicy(policy));
    }

    /** 更新准入行 (方法/路径为身份不可改; 可改档位/权限/状态/备注) */
    @PutMapping("/{id}")
    public Result<IamEndpointPolicy> update(@PathVariable("id") Long id,
                                            @RequestBody IamEndpointPolicy policy) {
        return Result.ok(endpointPolicyService.updatePolicy(id, policy));
    }

    /** 删除准入行 (直查模式下删除即刻对所有实例生效) */
    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable("id") Long id) {
        endpointPolicyService.deletePolicy(id);
        return Result.ok(null);
    }
}
