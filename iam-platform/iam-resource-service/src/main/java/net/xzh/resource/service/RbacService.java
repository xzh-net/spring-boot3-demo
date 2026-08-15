package net.xzh.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.entity.SysPermission;
import net.xzh.resource.entity.SysRole;
import net.xzh.resource.entity.SysRolePermission;
import net.xzh.resource.entity.SysUserRole;
import net.xzh.resource.mapper.SysPermissionMapper;
import net.xzh.resource.mapper.SysRoleMapper;
import net.xzh.resource.mapper.SysRolePermissionMapper;
import net.xzh.resource.mapper.SysUserRoleMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 角色/权限管理服务 (iam_authorization RBAC).
 * <p>
 * 仅操作业务 RBAC 表: sys_role / sys_permission / sys_role_permission / sys_user_role.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RbacService {

    private final SysRoleMapper roleMapper;
    private final SysPermissionMapper permissionMapper;
    private final SysRolePermissionMapper rolePermissionMapper;
    private final SysUserRoleMapper userRoleMapper;

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
        if (StringUtils.hasText(role.getName())) existing.setName(role.getName());
        if (role.getRemark() != null) existing.setRemark(role.getRemark());
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

    @Transactional
    public void deleteRole(Long id) {
        SysRole role = roleMapper.selectById(id);
        if (role == null) throw new IllegalArgumentException("角色不存在: " + id);
        roleMapper.deleteById(id);
        rolePermissionMapper.delete(new QueryWrapper<SysRolePermission>().eq("role_id", id));
        userRoleMapper.delete(new QueryWrapper<SysUserRole>().eq("role_id", id));
        log.info("删除角色 id={}, code={}", id, role.getCode());
    }

    // ==================== 权限 ====================

    public List<SysPermission> listPermissions() {
        return permissionMapper.selectList(new QueryWrapper<SysPermission>().orderByAsc("id"));
    }

    @Transactional
    public void createPermission(SysPermission permission) {
        if (!StringUtils.hasText(permission.getCode())) {
            throw new IllegalArgumentException("权限标识不能为空");
        }
        if (permissionMapper.selectCount(new QueryWrapper<SysPermission>().eq("code", permission.getCode())) > 0) {
            throw new IllegalArgumentException("权限标识已存在: " + permission.getCode());
        }
        if (!StringUtils.hasText(permission.getType())) permission.setType("app");
        permission.setCreateTime(LocalDateTime.now());
        permissionMapper.insert(permission);
        log.info("新增权限 code={}", permission.getCode());
    }

    @Transactional
    public void updatePermission(Long id, SysPermission permission) {
        SysPermission existing = permissionMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("权限不存在: " + id);
        if (StringUtils.hasText(permission.getName())) existing.setName(permission.getName());
        if (permission.getRemark() != null) existing.setRemark(permission.getRemark());
        if (StringUtils.hasText(permission.getType())) existing.setType(permission.getType());
        permissionMapper.updateById(existing);
        log.info("更新权限 id={}, code={}", id, existing.getCode());
    }

    @Transactional
    public void deletePermission(Long id) {
        SysPermission permission = permissionMapper.selectById(id);
        if (permission == null) throw new IllegalArgumentException("权限不存在: " + id);
        permissionMapper.deleteById(id);
        rolePermissionMapper.delete(new QueryWrapper<SysRolePermission>().eq("permission_id", id));
        log.info("删除权限 id={}, code={}", id, permission.getCode());
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
}