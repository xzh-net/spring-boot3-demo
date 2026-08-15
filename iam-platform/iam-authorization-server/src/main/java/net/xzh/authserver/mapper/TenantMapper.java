package net.xzh.authserver.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.authserver.entity.Tenant;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TenantMapper extends BaseMapper<Tenant> {
}
