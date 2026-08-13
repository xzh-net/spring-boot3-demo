package net.xzh.resource.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import net.xzh.resource.entity.OAuth2RegisteredClient;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface OAuth2RegisteredClientMapper extends BaseMapper<OAuth2RegisteredClient> {

    @Select("SELECT * FROM oauth2_registered_client WHERE client_id = #{clientId} LIMIT 1")
    OAuth2RegisteredClient selectByClientId(@Param("clientId") String clientId);

    /**
     * 查询除指定 clientId 外的全部客户端 (排除 portal-app 自身).
     */
    @Select("SELECT * FROM oauth2_registered_client WHERE client_id != #{excludeClientId} ORDER BY id ASC")
    List<OAuth2RegisteredClient> selectAllExcluding(@Param("excludeClientId") String excludeClientId);
}