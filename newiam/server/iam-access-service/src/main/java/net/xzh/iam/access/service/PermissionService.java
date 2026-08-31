package net.xzh.iam.access.service;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import net.xzh.iam.access.mapper.SysPermissionMapper;
import net.xzh.iam.access.mapper.SysRoleMapper;

/**
 * 身份/权限解析服务 (DB 版).
 * <p>
 * V6.2: 移除影子用户表 sys_user, 以 token sub (业务用户编码 user_code)
 * 直接经 sys_user_role → sys_role/sys_permission 解析角色与权限。
 * </p>
 */
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final SysRoleMapper sysRoleMapper;
    private final SysPermissionMapper sysPermissionMapper;

    /** 用户拥有的角色编码 (ADMIN / USER) */
    public List<String> findRoleCodes(String userCode) {
        return sysRoleMapper.selectRoleCodesByUserCode(userCode);
    }

    /** 用户拥有的权限编码集合 (app:portal / app:oa / ...) */
    public Set<String> findPermissions(String userCode) {
        return new LinkedHashSet<>(sysPermissionMapper.selectPermissionCodesByUserCode(userCode));
    }

    /** 当前用户是否可访问指定应用 (权限标识 app:xxx) */
    public boolean canAccessApp(String userCode, String appCode) {
        return findPermissions(userCode).contains(appCode);
    }
}