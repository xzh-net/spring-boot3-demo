package net.xzh.resource.service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.xzh.resource.entity.SysUser;
import net.xzh.resource.mapper.SysUserMapper;

/**
 * 身份/权限解析服务 (DB 版).
 * <p>
 * 通过内省 token 中的 sub (用户名) 到 MySQL 的 RBAC 表
 * (sys_user / sys_user_role / sys_role / sys_role_permission / sys_permission)
 * 解析出当前用户的身份信息与权限集合 (如 app:portal / app:oa ...)。
 * </p>
 */
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final SysUserMapper sysUserMapper;

    /** 按用户名查询用户身份 (sub → sys_user) */
    public SysUser findByUsername(String username) {
        return sysUserMapper.selectByUsername(username);
    }

    /** 用户拥有的角色编码 (ADMIN / USER) */
    public List<String> findRoleCodes(String username) {
        return sysUserMapper.selectRoleCodes(username);
    }

    /** 用户拥有的权限编码集合 (app:portal / app:oa / ...) */
    public Set<String> findPermissions(String username) {
        return new LinkedHashSet<>(sysUserMapper.selectPermissionCodes(username));
    }

    /** 当前用户是否可访问指定应用 (权限标识 app:xxx) */
    public boolean canAccessApp(String username, String appCode) {
        return findPermissions(username).contains(appCode);
    }
}