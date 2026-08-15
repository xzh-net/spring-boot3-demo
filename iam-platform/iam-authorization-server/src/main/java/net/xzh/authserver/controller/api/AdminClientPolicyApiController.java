package net.xzh.authserver.controller.api;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.entity.ClientPolicy;
import net.xzh.authserver.entity.OAuth2RegisteredClient;
import net.xzh.authserver.mapper.ClientPolicyMapper;
import net.xzh.authserver.service.ClientService;
import net.xzh.authserver.vo.ClientPolicyVO;

/**
 * 三域管理 API — 客户端准入策略域 (/api/admin/policies).
 * <p>
 * 令牌签发准入配置 (原 yaml client-identity-policy) 的表化维护接口,
 * 经 Order(2) 安全链保护 (Bearer + ROLE_ADMIN)。
 * </p>
 */
@RestController
@RequestMapping("/api/admin/policies")
@RequiredArgsConstructor
public class AdminClientPolicyApiController {

    private final ClientPolicyMapper clientPolicyMapper;
    private final ClientService clientService;

    /**
     * 列出全部客户端的准入策略 (未配置策略的客户端默认放行).
     */
    @GetMapping
    public Result<List<ClientPolicyVO>> list() {
        Map<String, ClientPolicy> policyByClient = clientPolicyMapper.selectList(null).stream()
                .collect(Collectors.toMap(ClientPolicy::getClientId, Function.identity(), (a, b) -> a));
        List<ClientPolicyVO> result = new ArrayList<>();
        for (OAuth2RegisteredClient client : clientService.list()) {
            ClientPolicy policy = policyByClient.get(client.getClientId());
            ClientPolicyVO vo = new ClientPolicyVO();
            vo.setClientId(client.getClientId());
            vo.setClientName(client.getClientName());
            vo.setAllowedRoles(policy == null ? null : policy.getAllowedRoles());
            vo.setStatus(policy == null ? null : policy.getStatus());
            vo.setRemark(policy == null ? null : policy.getRemark());
            vo.setCreateTime(policy == null ? null : policy.getCreateTime());
            result.add(vo);
        }
        return Result.ok(result);
    }

    /**
     * 查询单个客户端的准入策略.
     */
    @GetMapping("/{clientId}")
    public Result<ClientPolicy> get(@PathVariable String clientId) {
        return Result.ok(clientPolicyMapper.selectOne(
                new QueryWrapper<ClientPolicy>().eq("client_id", clientId)));
    }

    /**
     * 新增或更新客户端准入策略 (按 client_id upsert).
     * <p>allowedRoles 为空或 * 表示不限制; 删除策略行则恢复默认放行。</p>
     */
    @PostMapping
    public Result<Void> upsert(@RequestBody ClientPolicyVO vo) {
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

    /**
     * 删除客户端准入策略 (恢复默认放行).
     */
    @DeleteMapping("/{clientId}")
    public Result<Void> delete(@PathVariable String clientId) {
        clientPolicyMapper.delete(new QueryWrapper<ClientPolicy>().eq("client_id", clientId));
        return Result.ok();
    }
}