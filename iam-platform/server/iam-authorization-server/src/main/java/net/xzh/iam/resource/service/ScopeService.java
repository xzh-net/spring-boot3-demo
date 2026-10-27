package net.xzh.iam.resource.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.OAuth2RegisteredClient;
import net.xzh.iam.auth.mapper.OAuth2RegisteredClientMapper;
import net.xzh.iam.resource.entity.SysPermission;
import net.xzh.iam.resource.entity.SysScope;
import net.xzh.iam.resource.entity.SysScopePermission;
import net.xzh.iam.resource.mapper.SysPermissionMapper;
import net.xzh.iam.resource.mapper.SysScopeMapper;
import net.xzh.iam.resource.mapper.SysScopePermissionMapper;
import net.xzh.iam.resource.vo.ScopeVO;

/**
 * 客户端授权范围 (scope) 服务 — 双维权限控制的客户端维度.
 * <p>
 * 展开链: oauth2_registered_client.scopes (Spring 标准列, 客户端持有 scope 码)
 * → sys_scope (启用态) → sys_scope_permission → sys_permission (启用态)。
 * 展开结果与用户 RBAC 码取交集后注入令牌 authorities (见 RbacAuthoritiesOpaqueTokenIntrospector):
 * <ul>
 *   <li>用户有码、客户端 scope 未含 → 不注入 (403): 防三方借用户身份越权;</li>
 *   <li>客户端有 scope、用户无码 → 不注入 (403): 防低权用户借高权客户端越权;</li>
 *   <li>客户端无业务 scope / scope 停用 / 客户端未知 → fail-closed 一码不放。</li>
 * </ul>
 * 字典只读: sys_scope / sys_scope_permission 增删改走 SQL 种子; 本服务只提供查询与展开。
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ScopeService {

    private final SysScopeMapper sysScopeMapper;
    private final SysScopePermissionMapper sysScopePermissionMapper;
    private final SysPermissionMapper sysPermissionMapper;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2RegisteredClientMapper registeredClientMapper;

    /**
     * 按客户端 clientId 展开业务权限码 (自省层调用).
     * <p>fail-closed: 客户端不存在 / 无 scope / 无可用 scope / 任一环节为空 → 空集。</p>
     */
    public Set<String> resolveClientBusinessCodes(String clientId) {
        if (!StringUtils.hasText(clientId)) {
            return Set.of();
        }
        RegisteredClient client;
        try {
            client = registeredClientRepository.findByClientId(clientId);
        } catch (Exception e) {
            log.warn("[Scope] 查客户端失败(fail-closed): clientId={}", clientId, e);
            return Set.of();
        }
        if (client == null || client.getScopes() == null || client.getScopes().isEmpty()) {
            return Set.of();
        }
        return expandScopeCodes(client.getScopes());
    }

    /**
     * scope 码集合 → 业务权限码 (启用态 scope ∩ 映射 ∩ 启用态权限码).
     * 非业务 scope (openid/profile/read/write 等未登记进 sys_scope 的) 自然被忽略。
     */
    public Set<String> expandScopeCodes(Set<String> scopeCodes) {
        if (scopeCodes == null || scopeCodes.isEmpty()) {
            return Set.of();
        }
        List<SysScope> scopes = sysScopeMapper.selectList(new QueryWrapper<SysScope>()
                .eq("status", 1).in("code", scopeCodes));
        if (scopes.isEmpty()) {
            return Set.of();
        }
        List<Long> scopeIds = scopes.stream().map(SysScope::getId).collect(Collectors.toList());
        List<SysScopePermission> links = sysScopePermissionMapper.selectList(
                new QueryWrapper<SysScopePermission>().in("scope_id", scopeIds));
        if (links.isEmpty()) {
            return Set.of();
        }
        List<Long> permIds = links.stream().map(SysScopePermission::getPermissionId).collect(Collectors.toList());
        List<SysPermission> perms = sysPermissionMapper.selectList(new QueryWrapper<SysPermission>()
                .eq("status", 1).in("id", permIds));
        return perms.stream().map(SysPermission::getCode)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /** 只读列表 (scope.html): scope 行 + 内含权限码 + 引用客户端 */
    public List<ScopeVO> listScopes() {
        List<SysScope> scopes = sysScopeMapper.selectList(new QueryWrapper<SysScope>().orderByAsc("id"));
        if (scopes.isEmpty()) {
            return List.of();
        }
        List<Long> scopeIds = scopes.stream().map(SysScope::getId).collect(Collectors.toList());

        // 映射 + 权限码 (全量含停用, 页面按 status 置灰)
        List<SysScopePermission> links = sysScopePermissionMapper.selectList(
                new QueryWrapper<SysScopePermission>().in("scope_id", scopeIds));
        Set<Long> permIds = links.stream().map(SysScopePermission::getPermissionId)
                .collect(Collectors.toSet());
        Map<Long, SysPermission> permById = permIds.isEmpty() ? Map.of()
                : sysPermissionMapper.selectList(new QueryWrapper<SysPermission>().in("id", permIds))
                        .stream().collect(Collectors.toMap(SysPermission::getId, Function.identity()));

        // 引用客户端: 读 oauth2_registered_client.scopes (CSV) 反向匹配 scope 码
        Set<String> scopeCodes = scopes.stream().map(SysScope::getCode).collect(Collectors.toSet());
        Map<String, List<String>> clientsByScopeCode = new java.util.HashMap<>();
        for (OAuth2RegisteredClient c : registeredClientMapper.selectList(null)) {
            if (!StringUtils.hasText(c.getScopes())) {
                continue;
            }
            for (String raw : c.getScopes().split(",")) {
                String code = raw.trim();
                if (scopeCodes.contains(code)) {
                    clientsByScopeCode.computeIfAbsent(code, k -> new ArrayList<>()).add(c.getClientId());
                }
            }
        }

        Map<Long, List<ScopeVO.PermissionRef>> refsByScopeId = links.stream()
                .filter(l -> permById.containsKey(l.getPermissionId()))
                .collect(Collectors.groupingBy(SysScopePermission::getScopeId,
                        Collectors.mapping(l -> {
                            SysPermission p = permById.get(l.getPermissionId());
                            return new ScopeVO.PermissionRef(p.getId(), p.getCode(), p.getName(), p.getStatus());
                        }, Collectors.toList())));

        List<ScopeVO> result = new ArrayList<>();
        for (SysScope s : scopes) {
            ScopeVO vo = new ScopeVO();
            vo.setId(s.getId());
            vo.setCode(s.getCode());
            vo.setName(s.getName());
            vo.setStatus(s.getStatus());
            vo.setRemark(s.getRemark());
            vo.setPermissions(refsByScopeId.getOrDefault(s.getId(), List.of()));
            vo.setClientIds(clientsByScopeCode.getOrDefault(s.getCode(), List.of()));
            result.add(vo);
        }
        return result;
    }
}
