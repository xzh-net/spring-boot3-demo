package net.xzh.authserver.security.authentication.grant;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/**
 * 密码授权模式专用认证令牌.
 * <p>
 * 封装密码授权流程中的请求参数，在 Converter → Provider 之间传递。
 * 由 {@link PasswordGrantAuthenticationConverter} 创建，
 * 由 {@link PasswordGrantAuthenticationProvider} 消费。
 * <p>
 * 继承自 {@link OAuth2AuthorizationGrantAuthenticationToken}，
 * 持有客户端主体（clientPrincipal）、资源所有者凭据（username/password）、
 * 请求的 scope 列表以及额外参数。
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /** 密码授权类型常量，Converter 和 Provider 共享此引用进行 grant 类型校验 */
    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    /** 已认证的客户端主体（OAuth2ClientAuthenticationToken），包含 RegisteredClient 信息 */
    private final Authentication clientPrincipal;

    /** 资源所有者的用户名 */
    private final String username;

    /** 资源所有者的密码（明文，由 Provider 使用 PasswordEncoder 验证后清除） */
    private final String password;

    /** 请求的 scope 集合（来自请求参数，经 Provider 校验合法性） */
    private final Set<String> scopes;

    /**
     * 构造密码授权令牌。
     *
     * @param clientPrincipal 已认证的客户端主体，不可为 null
     * @param username        资源所有者用户名，不可为 null
     * @param password        资源所有者密码，不可为 null
     * @param scopes          请求的 scope 集合，可为空集合
     * @param additionalParameters 额外参数（透传非标准参数），可为 null
     */
    public PasswordGrantAuthenticationToken(
            Authentication clientPrincipal,
            String username,
            String password,
            Set<String> scopes,
            Map<String, Object> additionalParameters) {
        super(PASSWORD, clientPrincipal,
                additionalParameters != null ? additionalParameters : Collections.emptyMap());
        this.clientPrincipal = clientPrincipal;
        this.username = username;
        this.password = password;
        this.scopes = scopes != null ? Set.copyOf(scopes) : Collections.emptySet();
    }

    /** 资源所有者的用户名 */
    public String getUsername() {
        return username;
    }

    /** 资源所有者的密码（明文） */
    public String getPassword() {
        return password;
    }

    /** 请求的 scope 集合（不可变） */
    public Set<String> getScopes() {
        return scopes;
    }

    /** 已认证的客户端主体 */
    public Authentication getClientPrincipal() {
        return clientPrincipal;
    }
}