package net.xzh.authserver.config;

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
     * 允许访问管理 API ({@code /api/admin/**}) 的客户端 client_id 白名单.
     * <p>
     * 管理类 API 仅接受白名单内客户端签发的令牌访问, 其余客户端即使持有 ADMIN_SERVICE_TOKEN
     * (管理服务凭证) 也无法调用, 达到管理资源的客户端级隔离保护。
     */
    private Set<String> adminClientIds = Set.of("admin-app");

    /**
     * 资源中心 (iam-resource-service) 基础地址.
     * <p>
     * 令牌签发准入需以用户业务 RBAC 角色判定, 角色权威在资源中心 (D6 内部接口)。
     */
    private String resourceServiceBaseUrl = "http://localhost:9010";

    /**
     * 服务令牌端点: 认证中心自身的令牌端点, 以 resource-server 客户端
     * client_credentials 换取 PORTAL_SERVICE_TOKEN 门户服务凭证令牌后调用资源中心内部接口。
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
     * 管理 M2M 凭证使用的客户端 ID (client_credentials, 默认 admin-m2m)。
     * 以该客户端在 service-token-endpoint 换取服务令牌, 资源中心按 client_id 白名单
     * 内省注入 ADMIN_SERVICE_TOKEN (管理服务凭证), 供管理端能力调用
     * (如删除用户联动清理, {@code DELETE /api/admin/users/{userCode}/data})。
     */
    private String adminServiceTokenClientId = "admin-m2m";

    /**
     * 获取管理 M2M 凭证使用的客户端密钥 (须与 oauth2_registered_client 中一致)。
     */
    private String adminServiceTokenClientSecret = "123456";
}