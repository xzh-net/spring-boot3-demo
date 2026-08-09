package net.xzh.authserver.vo;

import lombok.Data;

@Data
public class SessionVO {

    private String authorizationId;
    private String principalName;
    private String registeredClientId;
    private String clientName;
    private String grantType;
    private String accessTokenExpiresAt;
    private String refreshTokenExpiresAt;
    private String loginTime;
    private String accessToken;
    private String refreshToken;
    private String clientIp;
    private String userAgent;
}
