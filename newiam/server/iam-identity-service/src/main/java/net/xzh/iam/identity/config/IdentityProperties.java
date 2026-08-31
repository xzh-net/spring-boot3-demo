package net.xzh.iam.identity.config;

import java.util.Set;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * 身份管理面对接配置 (前缀 {@code identity.*})。
 */
@Data
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {

    /** 认证中心根地址 (身份供给内部 API 所在) */
    private String authBaseUrl = "http://localhost:9000";

    /** 权限中心根地址 (删用户联动清理 RBAC / 登录策略所在) */
    private String accessBaseUrl = "http://localhost:9010";

    /** 服务令牌端点 (认证中心令牌端点, M2M client_credentials) */
    private String serviceTokenEndpoint = "http://localhost:9000/oauth2/token";

    /** 管理 M2M 服务身份 client_id (本服务调用下游的唯一机器身份) */
    private String m2mClientId = "admin-m2m";

    /** 管理 M2M 服务身份 client_secret */
    private String m2mClientSecret = "123456";

    /**
     * 允许调用本管理面的客户端白名单 (管理台用户令牌的 client_id, 默认 admin-app)。
     * 叠加 ADMIN_SERVICE_TOKEN 准入共同裁决。
     */
    private Set<String> adminClientIds = Set.of("admin-app");
}
