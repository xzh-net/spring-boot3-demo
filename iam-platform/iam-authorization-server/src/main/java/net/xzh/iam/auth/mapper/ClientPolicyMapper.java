package net.xzh.iam.auth.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import net.xzh.iam.auth.entity.ClientPolicy;

/**
 * 客户端准入策略数据访问接口 (iam_client_policy).
 */
@Mapper
public interface ClientPolicyMapper extends BaseMapper<ClientPolicy> {
}