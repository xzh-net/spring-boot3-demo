package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 客户端授权范围字典实体 (sys_scope).
 * <p>
 * 双维权限控制的"客户端维度粗分组" — 结构上对标用户维度的 sys_role:
 * 一个 scope = 一组权限码的具名捆绑 (N:N 映射见 sys_scope_permission)。
 * 客户端经 oauth2_registered_client.scopes 列持有 scope 码 (Spring 标准列作连接表),
 * 自省时 scope 展开码 ∩ 用户 RBAC 码 = 令牌实际业务权限 (fail-closed)。
 * <p>
 * 只读字典: 增删改走 SQL 种子 (iam.sql), 页面 (scope.html) 仅展示。
 * </p>
 */
@Data
@TableName("sys_scope")
public class SysScope {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** scope 码 (如 admin.full), 客户端注册串引用此码 */
    private String code;

    /** 展示名 (如 管理端全量) */
    private String name;

    /** 状态: 1=启用, 0=停用 (停用则展开剔除, 客户端等同一码不放) */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
