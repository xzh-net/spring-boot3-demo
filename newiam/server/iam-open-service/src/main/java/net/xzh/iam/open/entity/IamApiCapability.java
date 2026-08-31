package net.xzh.iam.open.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 开放能力登记实体 (iam_authorization.iam_api_capability).
 * <p>
 * 暴露给开发者的 API 能力: 以 (method, path_pattern) 作为能力路由, 与 iam_capability_subscription
 * 一起构成开发者能力准入 (scheme B: /api/capability/** 命名空间专属引擎, 不读 iam_client_policy)。
 * </p>
 */
@Data
@TableName("iam_api_capability")
public class IamApiCapability {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK) */
    private String tenantCode;

    /** 能力编码 (业务唯一, 如 contact:query) */
    private String capabilityCode;

    private String capabilityName;

    /** HTTP 方法 */
    private String method;

    /** 路径模式 (Ant 风格, 如 /api/capability/contacts/{id}) */
    private String pathPattern;

    /** 令牌所需 scope (逗号分隔, 空=不限制) */
    private String requiredScopes;

    /** 归属 (产品线/部门) */
    private String owner;

    /** 全局 QPS 上限 (0=不限制; 限流计数另表) */
    private Integer qpsLimit;

    /** 状态: 1=启用, 0=停用 */
    private Integer status;

    private String remark;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}