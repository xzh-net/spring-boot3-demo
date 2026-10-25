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
     * 允许访问管理 API ({@code /api/admin/**}) 的客户端 client_id 白名单.
     * <p>
     * 管理类 API 仅接受白名单内客户端签发的令牌访问, 其余客户端即使持有 ADMIN_SERVICE_TOKEN
     * (管理服务凭证) 也无法调用, 达到管理资源的客户端级隔离保护。
     */
    private Set<String> adminClientIds = Set.of("admin-app");

    /**
     * 服务令牌判定兜底: 列表内 client_id 且无 grant_type 属性的令牌视为「服务间 M2M」
     * 令牌 (注入 PORTAL_SERVICE_TOKEN)。与 internal 域硬规则解耦。
     */
    private Set<String> serviceClientIds = Set.of();

    /**
     * 门户客户端白名单: 仅列表内客户端签发的令牌可访问 portal 域接口
     * ({@code /api/public/**}), 内省时注入 PORTAL_SERVICE_TOKEN 作为门户门票。
     */
    private Set<String> portalClientIds = Set.of("portal-app");
}