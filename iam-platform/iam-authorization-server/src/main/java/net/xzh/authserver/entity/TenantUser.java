package net.xzh.authserver.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 租户-用户关系实体 (iam_identity.iam_tenant_user, 一人可属多租户).
 * <p>V6.4: 下放引用全部采用业务编码 (tenant_code / user_code), 不引用内部自增主键,
 * 便于租户成员关系跨库/跨服务引用 (离开认证库时使用编码而非内部 ID)。
 */
@Data
@TableName("iam_tenant_user")
public class TenantUser {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 租户编码 (关联 iam_tenant.tenant_code) */
    private String tenantCode;

    /** 业务用户编码 (关联 sys_user.user_code) */
    private String userCode;

    private String tenantUsername;

    private Boolean status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
