package net.xzh.iam.auth.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.auth.entity.TenantUser;

@Mapper
public interface TenantUserMapper extends BaseMapper<TenantUser> {

    @Select("SELECT t.id, t.tenant_code, t.tenant_name, t.status, t.create_time, t.update_time " +
            "FROM iam_tenant t JOIN iam_tenant_user tu ON tu.tenant_code = t.tenant_code " +
            "WHERE tu.user_code = #{userCode}")
    List<net.xzh.iam.auth.entity.Tenant> selectTenantsOfUser(@Param("userCode") String userCode);
}
