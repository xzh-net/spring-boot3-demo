package net.xzh.authserver.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.authserver.entity.TenantUser;

@Mapper
public interface TenantUserMapper extends BaseMapper<TenantUser> {

    @Select("SELECT t.id, t.tenant_code, t.tenant_name, t.status, t.create_time, t.update_time " +
            "FROM iam_tenant t JOIN iam_tenant_user tu ON tu.tenant_id = t.id " +
            "WHERE tu.user_id = #{userId}")
    List<net.xzh.authserver.entity.Tenant> selectTenantsOfUser(@Param("userId") Long userId);
}
