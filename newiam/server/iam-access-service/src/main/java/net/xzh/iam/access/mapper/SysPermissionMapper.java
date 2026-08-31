package net.xzh.iam.access.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.access.entity.SysPermission;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysPermissionMapper extends BaseMapper<SysPermission> {

    /**
     * 查询用户 (按业务用户编码 user_code) 拥有的权限编码集合.
     * sys_user_role → sys_role_permission → sys_permission
     */
    @Select("SELECT DISTINCT p.code FROM sys_permission p " +
            "JOIN sys_role_permission rp ON rp.permission_id = p.id " +
            "JOIN sys_role r ON r.id = rp.role_id " +
            "JOIN sys_user_role ur ON ur.role_id = r.id " +
            "WHERE ur.user_code = #{userCode}")
    List<String> selectPermissionCodesByUserCode(@Param("userCode") String userCode);

    @Select("SELECT rp.permission_id FROM sys_role_permission rp WHERE rp.role_id = #{roleId}")
    List<Long> selectPermissionIdsByRoleId(@Param("roleId") Long roleId);
}