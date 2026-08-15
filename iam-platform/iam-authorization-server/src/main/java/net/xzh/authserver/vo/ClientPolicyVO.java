package net.xzh.authserver.vo;

import java.time.LocalDateTime;

import lombok.Data;

/**
 * 客户端准入策略视图对象 (管理 API).
 */
@Data
public class ClientPolicyVO {

    /** 客户端 ID (关联 oauth2_registered_client.client_id) */
    private String clientId;

    /** 客户端名称 (展示用) */
    private String clientName;

    /** 允许访问的角色编码列表 (逗号分隔, 空或 * 表示不限制) */
    private String allowedRoles;

    /** 是否启用 */
    private Boolean status;

    private String remark;

    private LocalDateTime createTime;
}