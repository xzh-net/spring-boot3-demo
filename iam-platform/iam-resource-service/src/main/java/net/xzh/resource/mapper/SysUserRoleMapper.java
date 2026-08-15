package net.xzh.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.resource.entity.SysUserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysUserRoleMapper extends BaseMapper<SysUserRole> {

    @Select("SELECT ur.role_id FROM sys_user_role ur WHERE ur.user_code = #{userCode}")
    List<Long> selectRoleIdsByUserCode(@Param("userCode") String userCode);
}