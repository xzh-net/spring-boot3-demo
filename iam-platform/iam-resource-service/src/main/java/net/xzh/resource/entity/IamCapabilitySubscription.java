package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 开放能力订阅实体 (iam_authorization.iam_capability_subscription).
 * <p>
 * 开发者客户端 (oauth2_registered_client.client_id) × 开放能力 的订阅关系: 准入时校验
 * status=1 且在有效期内; 取消订阅只置 status=0 + revoke_time, 不物理删除。
 * 用量计数 (qps/quota) 本期仅登记断言, 实际限流计数另表 (二期)。
 * </p>
 */
@Data
@TableName("iam_capability_subscription")
public class IamCapabilitySubscription {

    @TableId(type = IdType.AUTO)
    private Long id;

    /** 租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK) */
    private String tenantCode;

    /** 订阅方客户端 (oauth2_registered_client.client_id, 逻辑引用, 非FK) */
    private String clientId;

    /** 能力编码 (逻辑引用 iam_api_capability.capability_code) */
    private String capabilityCode;

    /** 环境: PROD=生产/TEST=测试 */
    private String env;

    /** 订阅 QPS 上限 (0=不限制) */
    private Integer qpsLimit;

    /** 每日调用次数上限 (0=不限制) */
    private Integer quotaDaily;

    /** 每月调用次数上限 (0=不限制) */
    private Integer quotaMonthly;

    /** 状态: 1=订阅中, 0=已取消 */
    private Integer status;

    private LocalDateTime subscribeTime;

    /** 到期时间 (NULL=长期有效) */
    private LocalDateTime expireTime;

    private LocalDateTime revokeTime;

    private LocalDateTime createTime;

    private LocalDateTime updateTime;
}