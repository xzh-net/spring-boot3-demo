package net.xzh.iam.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.auth.entity.Tenant;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface TenantMapper extends BaseMapper<Tenant> {
}
