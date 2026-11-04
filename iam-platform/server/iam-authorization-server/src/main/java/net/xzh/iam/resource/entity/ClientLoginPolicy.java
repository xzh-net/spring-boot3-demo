package net.xzh.iam.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 客户端登录准入实体 (client_login_policy).
 * <p>
 * 登录维度的原生表达: 「哪个客户端允许哪些主体(角色/用户/所有人)登录」。
 * 与授权维度正交 — 本表只裁决 ①签发准入 (能否登录), 不参与 ②自省层业务码注入
 * (登录后令牌带哪些业务码仍由 用户 RBAC 码 ∩ 客户端 scope 展开码 决定)。
 * <p>
 * allow-list 语义 (fail-closed): 无任何启用行 = 拒绝所有登录; 不支持 DENY 行,
 * 未知 subject_type 视为不命中。写入口 (管理 API/页面) 待评估后补, 当前仅 SQL 种子。
 * </p>
 */
@Data
@TableName("client_login_policy")
public class ClientLoginPolicy {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** OAuth2 client_id (逻辑引用 oauth2_registered_client.client_id, 无外键) */
    private String clientId;

    /** 主体类型: ROLE=角色 / USER=用户 / ANY=所有已登录用户 */
    private String subjectType;

    /** 主体ID: ROLE=sys_role.code / USER=user_code / ANY=空串 */
    private String subjectId;

    /** 状态: 1=启用, 0=停用 (停用行不参与判定) */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
