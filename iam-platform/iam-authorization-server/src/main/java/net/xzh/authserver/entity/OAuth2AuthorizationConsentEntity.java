package net.xzh.authserver.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("oauth2_authorization_consent")
public class OAuth2AuthorizationConsentEntity {

    private String registeredClientId;

    private String principalName;

    private String authorities;

    /** 首次授权时间 (只在 insert 时写入, 后续 authorities 更新不改动) */
    private LocalDateTime firstGrantTime;

    /** 非数据库字段, 仅用于管理端展示客户端名称 */
    @TableField(exist = false)
    private String clientName;

    /** 非数据库字段, 仅用于管理端展示该 (client, user) 的所有授权类型 */
    @TableField(exist = false)
    private List<String> grantTypes;
}
