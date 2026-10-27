package net.xzh.iam.auth.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.iam.auth.entity.OAuth2RegisteredClient;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface OAuth2RegisteredClientMapper extends BaseMapper<OAuth2RegisteredClient> {

    @Select("SELECT * FROM oauth2_registered_client WHERE client_id = #{clientId} LIMIT 1")
    OAuth2RegisteredClient selectByClientId(@Param("clientId") String clientId);

    @Select("SELECT * FROM oauth2_registered_client WHERE client_id != #{clientId}")
    List<OAuth2RegisteredClient> selectAllExcluding(@Param("clientId") String clientId);
}
