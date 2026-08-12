package net.xzh.authserver.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

import lombok.Data;

/**
 * OAuth2 授权记录表 — 记录谁、在什么时间、向哪个客户端、授予了什么权限。
 * 与 oauth2_authorization_consent 不同, 本表是历史日志, 保留撤销记录。
 */
@Data
@TableName("oauth2_authorization_record")
public class OAuth2AuthorizationRecordEntity {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 客户端 ID (对应 oauth2_registered_client.client_id) */
    private String registeredClientId;

    /** 客户端名称 (冗余字段, 方便查询展示) */
    private String clientName;

    /** 用户名 (principal name) */
    private String principalName;

    /** 授予的权限 (scope 列表, 逗号分隔) */
    private String grantedAuthorities;

    /** 授权时间 */
    private LocalDateTime grantTime;

    /** 撤销时间 (nullable, status=revoked 时有值) */
    private LocalDateTime revokeTime;

    /** 状态: active=有效 / revoked=已撤销 */
    private String status;

    /** 授权类型: authorization_code / urn:ietf:params:oauth:grant-type:device_code / password 等 (原始 grant_type 值) */
    private String grantType;
}
