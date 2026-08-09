package net.xzh.authserver.mapper;

import java.util.List;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.authserver.entity.OAuth2AuthorizationConsentEntity;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface OAuth2AuthorizationConsentMapper extends BaseMapper<OAuth2AuthorizationConsentEntity> {

    @Select("SELECT * FROM oauth2_authorization_consent WHERE registered_client_id = #{registeredClientId} AND principal_name = #{principalName} LIMIT 1")
    OAuth2AuthorizationConsentEntity selectById(@Param("registeredClientId") String registeredClientId,
                                                @Param("principalName") String principalName);

    @Select("SELECT * FROM oauth2_authorization_consent ORDER BY principal_name, registered_client_id")
    List<OAuth2AuthorizationConsentEntity> listAll();

    @Update("UPDATE oauth2_authorization_consent SET authorities = #{authorities} WHERE registered_client_id = #{registeredClientId} AND principal_name = #{principalName}")
    int updateById(OAuth2AuthorizationConsentEntity entity);

    @Delete("DELETE FROM oauth2_authorization_consent WHERE registered_client_id = #{registeredClientId} AND principal_name = #{principalName}")
    int deleteById(@Param("registeredClientId") String registeredClientId,
                   @Param("principalName") String principalName);
}
