package net.xzh.authserver.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.authserver.entity.SysUser;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface SysUserMapper extends BaseMapper<SysUser> {
}
