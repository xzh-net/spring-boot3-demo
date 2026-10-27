package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 权限码字典实体 (sys_permission).
 * <p>
 * 每行 = 一个可授予的 API 权限码 (如 user:read); URL→码绑定见
 * iam_endpoint_policy.required_authority (资源接口准入策略表)。
 * 运行时经用户令牌注入 (RbacAuthoritiesOpaqueTokenIntrospector), 端点准入按码裁决。
 * </p>
 */
@Data
@TableName("sys_permission")
public class SysPermission {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 权限标识 (API 权限码, 如 user:read) */
    private String code;

    private String name;

    /** 状态: 1=启用, 0=停用 */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
