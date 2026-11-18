package net.xzh.iam.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.resource.entity.IamEndpointPermission;
import org.apache.ibatis.annotations.Mapper;

/**
 * 端点↔权限绑定 Mapper (iam_endpoint_permission, 只读加载与事务内维护).
 */
@Mapper
public interface IamEndpointPermissionMapper extends BaseMapper<IamEndpointPermission> {
}
