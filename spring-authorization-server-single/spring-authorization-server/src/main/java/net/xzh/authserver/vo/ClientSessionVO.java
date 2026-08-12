package net.xzh.authserver.vo;

import lombok.Data;

/**
 * 客户端会话视图 (层级模型的最内层).
 * <p>
 * 一个客户端会话对应一个 OAuth2Authorization 记录, 表示某用户在某客户端上的授权.
 */
@Data
public class ClientSessionVO {

    /** OAuth2Authorization ID */
    private String authorizationId;
    /** 客户端 ID (registered client ID) */
    private String registeredClientId;
    /** 客户端名称 */
    private String clientName;
    /** 授权类型 */
    private String grantType;
    /** 登录时间 (access_token 签发时间) */
    private String loginTime;
    /** Access Token 过期时间 */
    private String accessTokenExpiresAt;
    /** Access Token 值 (用于复制) */
    private String accessToken;
    /** Refresh Token 值 (用于复制) */
    private String refreshToken;
    /** 客户端 IP */
    private String clientIp;
    /** User-Agent */
    private String userAgent;
    /** 关联的 SSO 会话 ID */
    private String ssoSessionId;
}
