package net.xzh.resource.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * OAuth2 注册客户端实体 (与认证中心 oauth2_registered_client 表同构).
 * 资源服务器仅查询该表用于公开客户端列表.
 */
@Data
@TableName("oauth2_registered_client")
public class OAuth2RegisteredClient {

    private String id;

    private String clientId;

    private LocalDateTime clientIdIssuedAt;

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