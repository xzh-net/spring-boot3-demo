package net.xzh.iam.access.controller.admin;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import net.xzh.iam.access.entity.ClientPolicy;
import net.xzh.iam.access.mapper.ClientPolicyMapper;
import net.xzh.iam.common.Result;

/**
 * 管理域 API — 客户端登录边界策略 (/api/admin/login-policies).
 * <p>
 * 从认证中心 /api/admin/policies 迁入: 策略表 (iam_client_policy) 已随 S5 归位权限中心,
 * 管理入口随之迁移, 与 endpoint-policies 同级维护。经 admin 域准入
 * (ADMIN_SERVICE_TOKEN) 保护, 供身份管理面/管理台调用。
 * <p>
 * 语义: 无策略行 / 停用 / allowed_roles 空或 * = 不限制; 否则按角色交集放行。
 * 客户端名录 (client_id 清单) 由认证中心 client 目录提供, 前端自行合并展示。
 */
@RestController
@RequestMapping("/api/admin/login-policies")
@RequiredArgsConstructor
public class AdminLoginPolicyController {

    private final ClientPolicyMapper clientPolicyMapper;

    /** 列出全部已配置的客户端准入策略 (未配置的客户端默认放行, 不在此列) */
    @GetMapping
    public Result<List<ClientPolicy>> list() {
        return Result.ok(clientPolicyMapper.selectList(
                new QueryWrapper<ClientPolicy>().orderByAsc("client_id")));
    }

    /** 查询单个客户端的准入策略 (未配置返回 null) */
    @GetMapping("/{clientId}")
    public Result<ClientPolicy> get(@PathVariable String clientId) {
        return Result.ok(clientPolicyMapper.selectOne(
                new QueryWrapper<ClientPolicy>().eq("client_id", clientId)));
    }

    /**
     * 新增或更新客户端准入策略 (按 client_id upsert).
     * <p>allowedRoles 为空或 * 表示不限制。</p>
     */
    @PostMapping
    public Result<Void> upsert(@RequestBody ClientPolicy vo) {
        if (vo.getClientId() == null || vo.getClientId().isBlank()) {
            return Result.fail("clientId 必填");
        }
        ClientPolicy existing = clientPolicyMapper.selectOne(
                new QueryWrapper<ClientPolicy>().eq("client_id", vo.getClientId()));
        if (existing == null) {
            ClientPolicy policy = new ClientPolicy();
            policy.setClientId(vo.getClientId());
            policy.setAllowedRoles(vo.getAllowedRoles());
            policy.setStatus(vo.getStatus() == null ? Boolean.TRUE : vo.getStatus());
            policy.setRemark(vo.getRemark());
            policy.setCreateTime(LocalDateTime.now());
            policy.setUpdateTime(LocalDateTime.now());
            clientPolicyMapper.insert(policy);
        } else {
            existing.setAllowedRoles(vo.getAllowedRoles());
            existing.setStatus(vo.getStatus() == null ? existing.getStatus() : vo.getStatus());
            existing.setRemark(vo.getRemark());
            existing.setUpdateTime(LocalDateTime.now());
            clientPolicyMapper.updateById(existing);
        }
        return Result.ok();
    }

    /** 删除客户端准入策略 (恢复默认放行) */
    @DeleteMapping("/{clientId}")
    public Result<Void> delete(@PathVariable String clientId) {
        clientPolicyMapper.delete(new QueryWrapper<ClientPolicy>().eq("client_id", clientId));
        return Result.ok();
    }
}
