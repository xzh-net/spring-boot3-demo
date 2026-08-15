package net.xzh.authserver.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 租户实体 (iam_identity.iam_tenant, 身份层权威).
 */
@Data
@TableName("iam_tenant")
public class Tenant {

    @TableId(type = IdType.AUTO)
    private Long id;

    private String tenantCode;

    private String tenantName;

    private Boolean status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
