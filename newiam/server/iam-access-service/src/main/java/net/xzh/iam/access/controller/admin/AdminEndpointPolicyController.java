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
import net.xzh.iam.access.entity.IamEndpointPolicy;
import net.xzh.iam.access.service.EndpointPolicyService;

import java.util.Map;

/**
 * 接口准入策略管理 API (资源中心管理端能力域).
 * <p>「页面看到所有准入点」数据源: 启动扫描已按 controller 分包播种 coded 规则, 本接口
 * 提供全量浏览 / 覆盖 (override) / 重置默认 / 手动重扫。</p>
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/endpoint-policies")
@RequiredArgsConstructor
public class AdminEndpointPolicyController {

    private final EndpointPolicyService endpointPolicyService;

    /** 准入点全量列表 (含停用与 override 来源标记) */
    @GetMapping
    public Result<List<IamEndpointPolicy>> list() {
        return Result.ok(endpointPolicyService.listAll());
    }

    /** 覆盖准入要求/状态 (source=coded → override) */
    @PutMapping("/{id}")
    public Result<IamEndpointPolicy> update(@PathVariable Long id,
                                            @RequestBody Map<String, Object> body) {
        String authority = String.valueOf(body.getOrDefault("requiredAuthority", ""));
        Integer status = body.get("status") == null ? null : Integer.valueOf(String.valueOf(body.get("status")));
        String remark = body.get("remark") == null ? null : String.valueOf(body.get("remark"));
        return Result.ok(endpointPolicyService.updatePolicy(id, authority, status, remark));
    }

    /** 重置为扫描默认 (删除当前行后按分包推导回补 coded) */
    @DeleteMapping("/{id}")
    public Result<Void> reset(@PathVariable Long id) {
        endpointPolicyService.resetToCoded(id);
        return Result.ok();
    }

    /** 手动重扫并返回新增条数 */
    @PostMapping("/rescan")
    public Result<Map<String, Object>> rescan() {
        int inserted = endpointPolicyService.rescan();
        return Result.ok(Map.of("inserted", inserted));
    }
}