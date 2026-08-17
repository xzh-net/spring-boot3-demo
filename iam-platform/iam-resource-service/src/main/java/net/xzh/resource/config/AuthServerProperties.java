package net.xzh.resource.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

import java.util.Set;

/**
 * 认证中心对接配置.
 * <p>
 * V6 数据分库后客户端表 (oauth2_registered_client) 归属于认证中心 (iam_identity),
 * 资源中心通过 client_credentials 服务令牌调用认证中心目录 API 获取客户端列表,
 * 不再直读数据库。配置项:
 * <ul>
 *   <li>{@code authserver.base-url}         — 认证中心根地址 (默认 http://localhost:9000)</li>
 *   <li>{@code authserver.client-id/secret} — 服务间调用使用的注册客户端 (oauth2_registered_client 中已配置)</li>
 *   <li>{@code authserver.service-client-ids} — 服务令牌判定兜底: 该列表内的 client_id 且无
 *       grant_type 属性（历史/特殊令牌）的令牌视为「服务间 M2M」令牌 (注入 PORTAL_SERVICE_TOKEN);
 *       <b>与 internal 域解耦</b>——internal 域为硬规则 (仅认证中心 resource-server 可调,
 *       见 EndpointAdmissionManager), 不受本配置影响 (默认 [resource-server])</li>
 *   <li>{@code authserver.portal-client-ids} — 门户客户端白名单: 仅列表内客户端签发的令牌可访问
 *       portal 域接口 (/api/public/**)——其用户令牌内省时额外注入 PORTAL_SERVICE_TOKEN 作为门户门票,
 *       门户信息不对任意客户端开放 (默认 [portal-app])</li>
 *   <li>{@code authserver.admin-m2m-client-ids} — 管理 M2M 凭证白名单: 列表内客户端签发的
 *       服务令牌视为「管理 M2M」(认证中心等以机器身份执行管理写, 如删除用户联动清理),
 *       内省时注入 ADMIN_SERVICE_TOKEN 管理服务凭证 (默认 [admin-m2m])</li>
 * </ul>
 * </p>
 */
@Data
@ConfigurationProperties(prefix = "authserver")
public class AuthServerProperties {

    private String baseUrl = "http://localhost:9000";

    private String clientId = "resource-server";

    private String clientSecret = "123456";

    /** 服务令牌判定兜底 (无 grant_type 属性的历史令牌): 见类注释. */
    private Set<String> serviceClientIds = Set.of("resource-server");

    /** 门户客户端白名单 (portal 域接口仅限这些客户端): 见类注释. */
    private Set<String> portalClientIds = Set.of("portal-app");

    /** 管理 M2M 凭证白名单 (client_id ∈ 该列表的服务令牌内省注入 ADMIN_SERVICE_TOKEN): 见类注释. */
    private Set<String> adminM2mClientIds = Set.of("admin-m2m");
}