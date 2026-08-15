package net.xzh.authserver.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import net.xzh.authserver.entity.ClientPolicy;

/**
 * 客户端准入策略数据访问接口 (iam_client_policy).
 */
@Mapper
public interface ClientPolicyMapper extends BaseMapper<ClientPolicy> {
}