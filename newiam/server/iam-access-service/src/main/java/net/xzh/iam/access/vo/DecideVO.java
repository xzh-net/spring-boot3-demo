package net.xzh.iam.access.vo;

import java.util.List;

import lombok.Data;

/**
 * 登录准入决策结果 (decide 接口响应体).
 * <p>
 * 认证中心登录链路唯一依赖的裁决契约: allowed=是否放行该 (user, client) 组合;
 * roles=用户业务角色快照 (认证中心用于注入令牌 claims)。
 */
@Data
public class DecideVO {

    /** 是否放行登录/签发 */
    private boolean allowed;

    /** 用户业务角色编码快照 (原样, 不拼 ROLE_ 前缀) */
    private List<String> roles;
}
