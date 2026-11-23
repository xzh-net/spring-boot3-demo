package net.xzh.iam.auth.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@TableName("oauth2_registered_client")
public class OAuth2RegisteredClient {

    private String id;

    private String clientId;

    private LocalDateTime clientIdIssuedAt;

    /**
     * A-P2-6: 此实体同时是 Redis 客户端缓存的 Jackson 序列化载荷
     * (JdbcRegisteredClientRepository writeValueAsString) —— 字段上禁止加
     * @JsonProperty(WRITE_ONLY)/@JsonIgnore 等出站抑制注解, 否则缓存丢 secret
     * → 鉴权 invalid_client (本条已踩坑: 首轮加 WRITE_ONLY 导致 admin-app 401)。
     * NON_NULL 安全: 仅在值为 null 时省略字段 (list() 剥空后响应不含该键;
     * 缓存写入时 secret 非空 → 照常序列化)。API 不回传的诉求在出站层解决。
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String clientSecret;

    private LocalDateTime clientSecretExpiresAt;

    private String clientName;

    private String clientAuthenticationMethods;

    private String authorizationGrantTypes;

    private String redirectUris;

    private String postLogoutRedirectUris;

    private String scopes;

    private String clientSettings;

    private String tokenSettings;
}
