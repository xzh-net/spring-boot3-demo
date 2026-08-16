package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 应用授权实体 (iam_authorization.iam_app_authorization).
 * <p>哪些主体可见/可访问哪些应用。channel_id=0 表示整个应用全渠道授权, &gt;0 表示仅该渠道。
 * subject_type: ROLE=角色 (subject_id=角色编码 sys_role.code) / USER=用户 (subject_id=业务用户编码 user_code) / ORG=组织 (subject_id=组织编码 iam_org.org_code)。
 * <p>V6.4: ROLE 主体由 sys_role.id 统一为 sys_role.code, 与 USER=user_code 的编码寻址风格一致;
 * 租户以 tenant_code 下放引用认证中心 iam_tenant。
 */
@Data
@TableName("iam_app_authorization")
public class IamAppAuthorization {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 租户编码 (关联认证中心 iam_tenant.tenant_code, 下放用编码而非内部 ID) */
    private String tenantCode;

    private Long appId;

    /** 渠道ID: 0=整个应用全渠道, >0=仅该渠道 */
    private Long channelId;

    /** 授权主体类型: ROLE=角色 / USER=用户 / ORG=组织 */
    private String subjectType;

    /** 授权主体ID (ROLE=角色编码 sys_role.code; USER=业务用户编码 user_code; ORG=组织编码 iam_org.org_code) */
    private String subjectId;

    /** 状态: 1=有效, 0=停用 */
    private Integer status;

    private LocalDateTime grantTime;

    private LocalDateTime revokeTime;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
