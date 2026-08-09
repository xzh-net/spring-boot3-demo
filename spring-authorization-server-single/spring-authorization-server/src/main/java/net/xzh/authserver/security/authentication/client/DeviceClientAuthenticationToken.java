package net.xzh.authserver.security.authentication.client;

import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Transient;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * 设备码 public client 认证令牌.
 * <p>
 * 继承自 {@link OAuth2ClientAuthenticationToken}, 用于在设备码授权流程中
 * 携带 public client (认证方法为 NONE) 的认证信息.
 * <p>
 * 参考: SAS 官方示例 sample.authentication.DeviceClientAuthenticationToken
 */
@Transient
public class DeviceClientAuthenticationToken extends OAuth2ClientAuthenticationToken {

    public DeviceClientAuthenticationToken(String clientId, ClientAuthenticationMethod clientAuthenticationMethod,
            @Nullable Object credentials, @Nullable Map<String, Object> additionalParameters) {
        super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
    }

    public DeviceClientAuthenticationToken(RegisteredClient registeredClient, ClientAuthenticationMethod clientAuthenticationMethod,
            @Nullable Object credentials) {
        super(registeredClient, clientAuthenticationMethod, credentials);
    }
}
