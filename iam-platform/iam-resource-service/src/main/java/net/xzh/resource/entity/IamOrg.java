package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 组织实体 (iam_authorization.iam_org).
 * <p>应用授权主体之一: iam_app_authorization.subject_type=ORG 时 subject_id 关联本表 id。
 */
@Data
@TableName("iam_org")
public class IamOrg {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 租户编码 (关联认证中心 iam_tenant.tenant_code, 下放用编码而非内部 ID) */
    private String tenantCode;

    /** 父组织ID: 0=根组织 */
    private Long parentId;

    /** 组织编码 (业务唯一, 如 RND) */
    private String orgCode;

    private String orgName;

    /** 组织类型: GROUP=集团/COMPANY=公司/DEPT=部门 */
    private String orgType;

    /** 排序 (小前大后) */
    private Integer sort;

    /** 状态: 1=启用, 0=禁用 */
    private Integer status;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
