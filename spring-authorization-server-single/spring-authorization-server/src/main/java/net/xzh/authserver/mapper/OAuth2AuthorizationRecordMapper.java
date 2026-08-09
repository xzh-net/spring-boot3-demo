package net.xzh.authserver.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Update;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import net.xzh.authserver.entity.OAuth2AuthorizationRecordEntity;

@Mapper
public interface OAuth2AuthorizationRecordMapper extends BaseMapper<OAuth2AuthorizationRecordEntity> {

    /**
     * 将指定客户端 + 用户的授权记录标记为已撤销, 并记录撤销时间。
     */
    @Update("UPDATE oauth2_authorization_record SET status = 'revoked', revoke_time = NOW() " +
            "WHERE registered_client_id = #{registeredClientId} " +
            "AND principal_name = #{principalName} " +
            "AND status = 'active'")
    int revokeActiveConsent(@Param("registeredClientId") String registeredClientId,
                            @Param("principalName") String principalName);
}
