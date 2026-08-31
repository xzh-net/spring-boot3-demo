package net.xzh.iam.auth.config;

import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * 认证中心自定义配置.
 * <p>
 * 绑定 yml 中 {@code authserver.*} 前缀的配置项。
 */
@Data
@ConfigurationProperties(prefix = "authserver")
public class AuthServerProperties {

    /**
     * 允许调用身份供给内部 API ({@code /api/internal/identity/**}) 的 M2M 服务身份白名单.
     * <p>
     * 内部 API 仅接受白名单内 client_credentials 客户端签发的服务令牌
     * (当前即身份管理面 iam-identity-service 所用的 admin-m2m 管理服务身份)。
     */
    private Set<String> internalIdentityClientIds = Set.of("admin-m2m");

    /**
     * 权限中心 (iam-access-service) 基础地址.
     * <p>
     * 登录准入决策 (decide) 问询目标: 规则与事实都在权限中心本地闭环。
     */
    private String accessServiceBaseUrl = "http://localhost:9010";

    /**
     * 服务令牌端点: 认证中心自身的令牌端点, 以 resource-server 客户端
     * client_credentials 换取服务令牌后调用权限中心内部决策接口。
     */
    private String serviceTokenEndpoint = "http://localhost:9000/oauth2/token";

    /**
     * 获取服务令牌使用的客户端 ID (须为注册的 client_credentials 客户端, 默认 resource-server)。
     */
    private String serviceTokenClientId = "resource-server";

    /**
     * 获取服务令牌使用的客户端密钥 (须与 oauth2_registered_client 中一致)。
     */
    private String serviceTokenClientSecret = "123456";

    /**
     * decide 决策缓存新鲜窗口 (秒): 窗口内直接命中缓存, 不发起远程问询。
     */
    private long decideCacheTtlSeconds = 30;

    /**
     * decide 决策缓存 max-stale 窗口 (秒): 权限中心不可达时沿用最后一次真实判定的最长时间,
     * 超过后 fail-closed 明确拒绝 (无猜测成分)。
     */
    private long decideMaxStaleSeconds = 600;
}
