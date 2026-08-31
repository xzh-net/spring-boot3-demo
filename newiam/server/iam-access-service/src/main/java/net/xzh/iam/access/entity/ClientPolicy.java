package net.xzh.iam.access.entity;

import java.time.LocalDateTime;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

import lombok.Data;

/**
 * 客户端登录边界策略 (iam_client_policy).
 * <p>
 * 从认证中心 iam_identity 迁入权限中心 iam_authorization_v2 —— 策略规则与角色事实
 * (sys_user_role) 首次同库, 登录准入判定在权限中心本地闭环, 认证中心只传达裁决结果。
 * <p>
 * 语义: client_id → 允许登录的角色集合。
 * <ul>
 *   <li>无策略行 / status=false → 默认放行 (不限制);</li>
 *   <li>allowed_roles 为空或 * → 放行全部;</li>
 *   <li>否则与用户业务角色求交集, 交集非空才放行。</li>
 * </ul>
 */
@Data
@TableName("iam_client_policy")
public class ClientPolicy {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 客户端 client_id (逻辑引用认证中心 oauth2_registered_client.client_id) */
    private String clientId;

    /** 允许登录的角色编码集合 (逗号分隔, * 或空 = 不限制) */
    private String allowedRoles;

    /** 是否启用 (false 等同无策略, 放行) */
    private Boolean status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}
