package net.xzh.iam.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import org.apache.ibatis.annotations.Mapper;

/**
 * 资源接口准入策略 Mapper (iam_endpoint, 资源行).
 */
@Mapper
public interface IamEndpointPolicyMapper extends BaseMapper<IamEndpointPolicy> {
}
