package net.xzh.iam.auth.vo;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

import java.util.Set;

@Data
public class ClientVO {

    private String id;
    private String clientId;
    private String clientName;
    /** A-P2-6: 只进不出 (WRITE_ONLY) —— create/update 仍接受输入, 响应不回传 (含哈希) */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String clientSecret;
    private Set<String> clientAuthenticationMethods;
    private Set<String> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> postLogoutRedirectUris;
    private Set<String> scopes;
    private boolean requireProofKey;
    private boolean requireAuthorizationConsent;
    /**
     * access_token 格式: REFERENCE (Opaque 不透明码) / SELF_CONTAINED (JWT).
     * 项目全局固定使用 REFERENCE, 前端只读展示, 不接受修改.
     */
    private String accessTokenFormat;
    private String accessTokenTimeToLive;
    private boolean reuseRefreshTokens;
    private String authorizationCodeTimeToLive;
    private String refreshTokenTimeToLive;
}
