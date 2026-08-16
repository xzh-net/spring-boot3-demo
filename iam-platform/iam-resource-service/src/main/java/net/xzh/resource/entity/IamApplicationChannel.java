package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 应用渠道实体 (iam_authorization.iam_application_channel).
 * <p>应用在 Web / 移动门户的形态与跳转地址, 并绑定该渠道独立的 OAuth2 SSO 客户端
 * (sso_client_id 逻辑引用认证中心 oauth2_registered_client.client_id, 密钥零落库方案 A)。
 */
@Data
@TableName("iam_application_channel")
public class IamApplicationChannel {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long appId;

    /** 渠道形态: WEB=Web 门户, MOBILE=移动门户 (可扩展 H5/MINI) */
    private String channelType;

    private String channelName;

    private String accessUrl;

    /** OAuth2 SSO 客户端 (跨库引用, 非 FK; API 形态可空) */
    private String ssoClientId;

    /** 密钥状态: 0=未配置, 1=已配置 (仅走 UI 展示; 密文存认证中心) */
    private Integer secretStatus;

    /** 客户端签发时间 (冗余认证中心 client_id_issued_at) */
    private LocalDateTime clientIssuedAt;

    /** 默认渠道: 1=是 (同应用仅一个), 0=否 */
    private Integer isDefault;

    private Integer sort;

    /** 状态: 1=启用, 0=禁用 */
    private Integer status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
