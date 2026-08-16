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
 *   <li>{@code authserver.service-client-ids} — 服务令牌白名单: 该列表内的 client_id 签发的令牌
 *       视为「服务间 M2M」令牌 (注入 PORTAL_SERVICE_TOKEN), 供 /api/internal/** 等内部接口鉴权;
 *       不在此列表内的客户端即使拿到令牌也不视为服务调用 (默认 [resource-server])</li>
 *   <li>{@code authserver.portal-client-ids} — 门户客户端白名单: 仅列表内客户端签发的令牌可访问
 *       portal 域接口 (/api/public/**)——其用户令牌内省时额外注入 PORTAL_SERVICE_TOKEN 作为门户门票,
 *       门户信息不对任意客户端开放 (默认 [portal-app])</li>
 * </ul>
 * </p>
 */
@Data
@ConfigurationProperties(prefix = "authserver")
public class AuthServerProperties {

    private String baseUrl = "http://localhost:9000";

    private String clientId = "resource-server";

    private String clientSecret = "123456";

    /** 服务令牌白名单 (M2M): 见类注释. */
    private Set<String> serviceClientIds = Set.of("resource-server");

    /** 门户客户端白名单 (portal 域接口仅限这些客户端): 见类注释. */
    private Set<String> portalClientIds = Set.of("portal-app");
}