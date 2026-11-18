package net.xzh.iam.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.entity.IamEndpointPermission;
import net.xzh.iam.resource.entity.SysPermission;
import net.xzh.iam.resource.entity.SysRole;
import net.xzh.iam.resource.entity.SysRolePermission;
import net.xzh.iam.resource.entity.SysScopePermission;
import net.xzh.iam.resource.entity.SysUserRole;
import net.xzh.iam.resource.mapper.IamEndpointPermissionMapper;
import net.xzh.iam.resource.mapper.SysPermissionMapper;
import net.xzh.iam.resource.mapper.SysRoleMapper;
import net.xzh.iam.resource.mapper.SysRolePermissionMapper;
import net.xzh.iam.resource.mapper.SysScopeMapper;
import net.xzh.iam.resource.mapper.SysScopePermissionMapper;
import net.xzh.iam.resource.mapper.SysUserRoleMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 角色/权限管理服务 (单库 iam RBAC).
 * <p>
 * 业务 RBAC 表: sys_role / sys_permission (权限码字典) / sys_role_permission / sys_user_role。
 * 端点绑定在 iam_endpoint_permission (1:N), 删除权限码前校验无绑定引用。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RbacService {

    /** 内置角色编码: 认证中心/资源中心硬编码引用 (RbacAuthoritiesOpaqueTokenIntrospector 依据 ADMIN/USER 判定令牌类别),
     *  禁止编辑元数据与删除, 但允许维护权限绑定。 */
    private static final Set<String> BUILTIN_ROLE_CODES = Set.of("ADMIN", "PORTAL", "THIRD_PARTY");

    private final SysRoleMapper roleMapper;
    private final SysPermissionMapper permissionMapper;
    private final SysRolePermissionMapper rolePermissionMapper;
    private final SysUserRoleMapper userRoleMapper;
    private final IamEndpointPermissionMapper endpointPermissionMapper;
    private final SysScopePermissionMapper scopePermissionMapper;
    private final SysScopeMapper sysScopeMapper;

    // ==================== 角色 ====================

    public List<Map<String, Object>> listRoles() {
        return roleMapper.selectList(null).stream().map(role -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("id", role.getId());
            item.put("code", role.getCode());
            item.put("name", role.getName());
            item.put("remark", role.getRemark());
            item.put("createTime", role.getCreateTime());
            item.put("updateTime", role.getUpdateTime());
            item.put("permissionIds", permissionMapper.selectPermissionIdsByRoleId(role.getId()));
            return item;
        }).toList();
    }

    public SysRole getRole(Long id) {
        return roleMapper.selectById(id);
    }

    @Transactional
    public void createRole(SysRole role) {
        if (!StringUtils.hasText(role.getCode())) {
            throw new IllegalArgumentException("角色编码不能为空");
        }
        if (roleMapper.selectCount(new QueryWrapper<SysRole>().eq("code", role.getCode())) > 0) {
            throw new IllegalArgumentException("角色编码已存在: " + role.getCode());
        }
        role.setCreateTime(LocalDateTime.now());
        role.setUpdateTime(role.getCreateTime());
        roleMapper.insert(role);
        log.info("新增角色 code={}", role.getCode());
    }

    @Transactional
    public void updateRole(Long id, SysRole role) {
        SysRole existing = roleMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("角色不存在: " + id);
        boolean builtin = BUILTIN_ROLE_CODES.contains(existing.getCode());
        if (builtin && !metadataUnchanged(existing, role)) {
            throw new IllegalArgumentException("内置角色 " + existing.getCode()
                    + " 不允许修改编码/名称/备注 (仅允许分配权限)");
        }
        if (!builtin) {
            // 编码不可修改 (服务层显式守卫, P0-2 包0): 登录准入 client_login_policy.subject_id
            // 以角色码字符串引用, 改码会使三端登录准入规则静默失效 (用户被拒登录且无报警)。
            // 此前 code 输入被静默忽略, 现改为明确拒绝; 内置角色已在上方整体拦截。
            if (StringUtils.hasText(role.getCode()) && !role.getCode().trim().equals(existing.getCode())) {
                throw new IllegalArgumentException("角色编码不可修改: " + existing.getCode()
                        + " (登录准入按角色码引用, 改码会使准入规则失效; 需要新编码请新建角色)");
            }
            if (StringUtils.hasText(role.getName())) existing.setName(role.getName());
            if (role.getRemark() != null) existing.setRemark(role.getRemark());
        }
        existing.setUpdateTime(LocalDateTime.now());
        roleMapper.updateById(existing);

        // 重新绑定权限
        if (role.getPermissionIds() != null) {
            rolePermissionMapper.delete(new QueryWrapper<SysRolePermission>().eq("role_id", id));
            for (Long permissionId : role.getPermissionIds()) {
                SysRolePermission rp = new SysRolePermission();
                rp.setRoleId(id);
                rp.setPermissionId(permissionId);
                rolePermissionMapper.insert(rp);
            }
        }
        log.info("更新角色 id={}, code={}", id, existing.getCode());
    }

    /** 内置角色校验: 编码/名称/备注均未改变 (空白视为等同 null, 前端分配权限仅回传当前值) */
    private boolean metadataUnchanged(SysRole existing, SysRole role) {
        boolean codeChanged = StringUtils.hasText(role.getCode())
                && !role.getCode().equals(existing.getCode());
        boolean nameChanged = StringUtils.hasText(role.getName())
                && !norm(role.getName()).equals(norm(existing.getName()));
        boolean remarkChanged = role.getRemark() != null
                && !norm(role.getRemark()).equals(norm(existing.getRemark()));
        return !codeChanged && !nameChanged && !remarkChanged;
    }

    private static String norm(String v) {
        return v == null ? "" : v.trim();
    }

    @Transactional
    public void deleteRole(Long id) {
        SysRole role = roleMapper.selectById(id);
        if (role == null) throw new IllegalArgumentException("角色不存在: " + id);
        if (BUILTIN_ROLE_CODES.contains(role.getCode())) {
            throw new IllegalArgumentException("内置角色 " + role.getCode()
                    + " 不允许删除 (其编码被认证中心/资源中心硬编码引用)");
        }
        roleMapper.deleteById(id);
        rolePermissionMapper.delete(new QueryWrapper<SysRolePermission>().eq("role_id", id));
        userRoleMapper.delete(new QueryWrapper<SysUserRole>().eq("role_id", id));
        log.info("删除角色 id={}, code={}", id, role.getCode());
    }

    // ==================== 权限码 ====================

    public List<SysPermission> listPermissions() {
        return permissionMapper.selectList(new QueryWrapper<SysPermission>().orderByAsc("id"));
    }

    @Transactional
    public void createPermission(SysPermission permission) {
        if (!StringUtils.hasText(permission.getCode())) {
            throw new IllegalArgumentException("权限码不能为空");
        }
        if (!StringUtils.hasText(permission.getName())) {
            throw new IllegalArgumentException("权限名称不能为空");
        }
        permission.setCode(permission.getCode().trim());
        if (permission.getStatus() == null) permission.setStatus(1);
        if (permissionMapper.selectCount(new QueryWrapper<SysPermission>()
                .eq("code", permission.getCode())) > 0) {
            throw new IllegalArgumentException("权限码已存在: " + permission.getCode());
        }
        permission.setCreateTime(LocalDateTime.now());
        permission.setUpdateTime(permission.getCreateTime());
        permissionMapper.insert(permission);
        // 组归属组合提交 (同一事务): 创建码 + 挂「组→码」映射, 任一步失败整体回滚
        syncPermissionScopes(permission.getId(), permission.getScopeIds());
        log.info("新增权限码 id={}, code={}, scopeIds={}", permission.getId(), permission.getCode(), permission.getScopeIds());
    }

    @Transactional
    public void updatePermission(Long id, SysPermission permission) {
        SysPermission existing = permissionMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("权限不存在: " + id);
        // 改名守卫已按终稿承诺放开 (P0-2 包1, V6.17 permission_id 化完成): 端点准入经稳定 id 关联,
        // 改名只改 sys_permission.code, 引用自动跟随不再失联。生效边界: 运行中实例的内存快照仍是
        // 启动时解析的旧码 → 新签发令牌 (内省读当前码) 与旧快照不匹配, 滚动重启后恢复;
        // 旧令牌携带旧码的窗口属令牌契约问题 (归 P0-1)。角色码改名守卫见 updateRole (subject_id 仍按码引用)。
        if (StringUtils.hasText(permission.getCode())) existing.setCode(permission.getCode().trim());
        if (StringUtils.hasText(permission.getName())) existing.setName(permission.getName());
        if (permission.getStatus() != null) existing.setStatus(permission.getStatus());
        if (permission.getRemark() != null) existing.setRemark(permission.getRemark());
        if (permissionMapper.selectCount(new QueryWrapper<SysPermission>()
                .eq("code", existing.getCode()).ne("id", id)) > 0) {
            throw new IllegalArgumentException("权限码已存在: " + existing.getCode());
        }
        existing.setUpdateTime(LocalDateTime.now());
        permissionMapper.updateById(existing);
        // 组归属组合提交 (同一事务): 更新码 + diff 同步「组→码」映射, 任一步失败整体回滚
        // (scopeIds=null 表示不改动映射)
        if (permission.getScopeIds() != null) {
            syncPermissionScopes(id, permission.getScopeIds());
        }
        log.info("更新权限码 id={}, code={}, status={}, scopeIds={}",
                id, existing.getCode(), existing.getStatus(), permission.getScopeIds());
    }

    /**
     * 把「组→码」映射同步为目标全集 (同一事务内调用, 失败整体回滚)。
     * <p>语义: 空数组=清空归属; 非空=同步为该集合 (diff: 删多、加缺、幂等)。</p>
     */
    private void syncPermissionScopes(Long permissionId, List<Long> targetScopeIds) {
        if (targetScopeIds == null) {
            return; // 不改动映射
        }
        // 去重 + 校验 scope 存在 (sys_scope_permission.scope_id 无 FK, 应用层校验防悬空)
        Set<Long> target = new java.util.LinkedHashSet<>();
        for (Long sid : targetScopeIds) {
            if (sid == null) {
                continue;
            }
            if (sysScopeMapper.selectById(sid) == null) {
                throw new IllegalArgumentException("授权范围不存在: " + sid);
            }
            target.add(sid);
        }
        // 现有映射
        List<SysScopePermission> existingLinks = scopePermissionMapper.selectList(
                new QueryWrapper<SysScopePermission>().eq("permission_id", permissionId));
        Set<Long> current = new java.util.LinkedHashSet<>();
        for (SysScopePermission link : existingLinks) {
            current.add(link.getScopeId());
        }
        // 删多 (移出)
        for (Long sid : current) {
            if (!target.contains(sid)) {
                scopePermissionMapper.delete(new QueryWrapper<SysScopePermission>()
                        .eq("permission_id", permissionId).eq("scope_id", sid));
            }
        }
        // 加缺 (加入)
        for (Long sid : target) {
            if (!current.contains(sid)) {
                SysScopePermission link = new SysScopePermission();
                link.setPermissionId(permissionId);
                link.setScopeId(sid);
                scopePermissionMapper.insert(link);
            }
        }
    }

    @Transactional
    public void deletePermission(Long id) {
        SysPermission permission = permissionMapper.selectById(id);
        if (permission == null) throw new IllegalArgumentException("权限不存在: " + id);
        // 删除守卫 (V6.20 拆表后按绑定表计数; 两处均有 FK 兜底):
        // ① 端点准入绑定 iam_endpoint_permission (endpoint 维度) — 直接删码会使绑定悬空;
        // ② 授权范围 sys_scope_permission — "删只在范围组、不在端点的码 → 悬空映射"窄缝。
        long refs = endpointPermissionMapper.selectCount(new QueryWrapper<IamEndpointPermission>()
                .eq("permission_id", id));
        if (refs > 0) {
            throw new IllegalArgumentException("权限正被 " + refs
                    + " 条端点权限绑定 (iam_endpoint_permission), 禁止删除; 请先在「资源准入」页取消其权限勾选或改用停用");
        }
        long scopeRefs = scopePermissionMapper.selectCount(new QueryWrapper<SysScopePermission>()
                .eq("permission_id", id));
        if (scopeRefs > 0) {
            throw new IllegalArgumentException("权限正被 " + scopeRefs
                    + " 个授权范围引用 (sys_scope_permission), 禁止删除; 请先在权限编辑弹窗中取消其「所属授权范围」勾选, 或改用停用");
        }
        rolePermissionMapper.delete(new QueryWrapper<SysRolePermission>().eq("permission_id", id));
        permissionMapper.deleteById(id);
        log.info("删除权限码 id={}, code={}", id, permission.getCode());
    }

    // ==================== 用户角色分配 ====================

    @Transactional
    public void assignRolesToUser(String userCode, List<Long> roleIds) {
        userRoleMapper.delete(new QueryWrapper<SysUserRole>().eq("user_code", userCode));
        for (Long roleId : roleIds) {
            SysUserRole ur = new SysUserRole();
            ur.setUserCode(userCode);
            ur.setRoleId(roleId);
            userRoleMapper.insert(ur);
        }
        log.info("为用户 user_code={} 分配角色 roleIds={}", userCode, roleIds);
    }

    public List<Long> listRoleIdsOfUser(String userCode) {
        return userRoleMapper.selectRoleIdsByUserCode(userCode);
    }

    /**
     * 删除用户全部角色绑定 (认证中心删除 sys_user 时联动清理, 避免跨库孤儿数据).
     *
     * @return 删除条数
     */
    @Transactional
    public int deleteUserRoleBindings(String userCode) {
        int deleted = userRoleMapper.delete(new QueryWrapper<SysUserRole>().eq("user_code", userCode));
        if (deleted > 0) {
            log.info("删除用户角色绑定 userCode={}, count={}", userCode, deleted);
        }
        return deleted;
    }
}