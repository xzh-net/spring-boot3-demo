package net.xzh.authserver.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * 客户端准入策略 (iam_client_policy).
 * <p>
 * 令牌签发准入由 yaml 硬编码迁移至该表后可运维配置:
 * 按 {@code client_id} 配置本客户端允许访问的角色编码集合,
 * 用户角色 (来自资源中心 RBAC) 与允许集合有交集才放行。
 * </p>
 */
@Data
@TableName("iam_client_policy")
public class ClientPolicy {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 客户端 ID (关联 oauth2_registered_client.client_id) */
    private String clientId;

    /**
     * 允许访问该客户端的角色编码列表 (逗号分隔, 如 ADMIN,OPERATOR).
     * <p>空串或 {@code *} 表示不限制 (放行任意登录用户)。</p>
     */
    private String allowedRoles;

    /** 是否启用: 1=启用, 0=停用 (停用等价于不配置策略, 默认放行) */
    private Boolean status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}