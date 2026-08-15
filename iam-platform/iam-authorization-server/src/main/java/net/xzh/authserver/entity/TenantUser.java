package net.xzh.authserver.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 租户-用户关系实体 (iam_identity.iam_tenant_user, 一人可属多租户).
 */
@Data
@TableName("iam_tenant_user")
public class TenantUser {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long tenantId;

    private Long userId;

    private String tenantUsername;

    private Boolean status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
