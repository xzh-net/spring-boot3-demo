package net.xzh.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.resource.entity.SysRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysRoleMapper extends BaseMapper<SysRole> {

    /**
     * 查询用户 (按业务用户编码 user_code) 拥有的角色编码 (如 ADMIN / USER).
     * sys_user_role → sys_role, 用户身份权威在认证中心 iam_identity.sys_user (无影子用户表)。
     */
    @Select("SELECT DISTINCT r.code FROM sys_role r " +
            "JOIN sys_user_role ur ON ur.role_id = r.id " +
            "WHERE ur.user_code = #{userCode}")
    List<String> selectRoleCodesByUserCode(@Param("userCode") String userCode);
}