package net.xzh.authserver.security.authentication.grant;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.ClientUserPolicyService;

/**
 * 授权码兑换的令牌签发准入包装器.
 * <p>
 * 在委托 SAS 默认的 {@link OAuth2AuthorizationCodeAuthenticationProvider} 签发令牌前,
 * 先按 code 反查授权记录, 用 {@code principalName} 执行"客户端 × 身份类型"准入策略;
 * 不通过则抛 {@code access_denied}, 不签发任何 token、不产生授权记录。
 * <p>
 * 客户端主体经公共 {@link Authentication#getPrincipal()} 获取
 * (SAS 7.x 的 {@code getClientPrincipal()} 为包级私有)。
 *
 * @see ClientUserPolicyService
 */
@Slf4j
public final class PolicyAwareAuthorizationCodeAuthenticationProvider implements AuthenticationProvider {

    private static final OAuth2TokenType AUTHORIZATION_CODE_TYPE = new OAuth2TokenType("code");

    private final OAuth2AuthorizationCodeAuthenticationProvider delegate;
    private final ClientUserPolicyService policyService;
    private final OAuth2AuthorizationService authorizationService;

    public PolicyAwareAuthorizationCodeAuthenticationProvider(OAuth2AuthorizationCodeAuthenticationProvider delegate,
            ClientUserPolicyService policyService, OAuth2AuthorizationService authorizationService) {
        this.delegate = delegate;
        this.policyService = policyService;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken codeAuth = (OAuth2AuthorizationCodeAuthenticationToken) authentication;
        if (codeAuth.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    codeAuth.getCode(), AUTHORIZATION_CODE_TYPE);
            if (authorization != null) {
                policyService.check(clientPrincipal.getRegisteredClient(), authorization.getPrincipalName());
            }
        }
        return delegate.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}