package net.xzh.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.resource.entity.SysUser;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysUserMapper extends BaseMapper<SysUser> {

    @Select("SELECT * FROM sys_user WHERE username = #{username} LIMIT 1")
    SysUser selectByUsername(@Param("username") String username);

    /**
     * 查询用户拥有的角色编码 (如 ADMIN / USER).
     * sys_user → sys_user_role → sys_role
     */
    @Select("SELECT DISTINCT r.code FROM sys_role r " +
            "JOIN sys_user_role ur ON ur.role_id = r.id " +
            "JOIN sys_user u ON u.id = ur.user_id " +
            "WHERE u.username = #{username}")
    List<String> selectRoleCodes(@Param("username") String username);

    /**
     * 查询用户拥有的权限编码 (如 app:portal / app:oa / app:crm / app:erp / app:bi).
     * sys_user → sys_user_role → sys_role_permission → sys_permission
     */
    @Select("SELECT DISTINCT p.code FROM sys_permission p " +
            "JOIN sys_role_permission rp ON rp.permission_id = p.id " +
            "JOIN sys_user_role ur ON ur.role_id = rp.role_id " +
            "JOIN sys_user u ON u.id = ur.user_id " +
            "WHERE u.username = #{username}")
    List<String> selectPermissionCodes(@Param("username") String username);
}