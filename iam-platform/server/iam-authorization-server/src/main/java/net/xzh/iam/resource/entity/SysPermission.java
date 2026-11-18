package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 权限码字典实体 (sys_permission).
 * <p>
 * 每行 = 一个可授予的 API 权限码 (如 user:read); URL→码绑定见
 * iam_endpoint_permission (端点绑定) 与 sys_scope_permission (授权范围)。
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

    /**
     * 所属授权范围组 id 集合 (非表字段, 仅随新增/编辑请求传输)。
     * <p>组合提交: 创建/更新权限码与同步「组→码」映射在<b>同一事务</b>内完成, 要么都成功要么都回滚。
     * 语义 = 目标全集: null=不改动映射; 空数组=清空归属; 非空=同步为该集合 (diff 增删)。</p>
     */
    @TableField(exist = false)
    private List<Long> scopeIds;
}
