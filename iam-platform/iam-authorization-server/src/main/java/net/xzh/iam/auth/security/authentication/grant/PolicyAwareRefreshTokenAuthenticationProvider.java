package net.xzh.iam.auth.security.authentication.grant;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.security.ClientUserPolicyService;

/**
 * 刷新令牌的令牌签发准入包装器.
 * <p>
 * 在委托 SAS 默认的 {@link OAuth2RefreshTokenAuthenticationProvider} 轮换/签发令牌前,
 * 先按 refresh_token 反查授权记录, 用 {@code principalName} 执行"客户端 × 身份类型"准入策略;
 * 不通过则抛 {@code access_denied}。由此覆盖"用户身份类型在签发后被调整（如由管理端改为客户端）"
 * 后仍可无限刷新令牌的场景。
 * <p>
 * 客户端主体经公共 {@link Authentication#getPrincipal()} 获取
 * (SAS 7.x 的 {@code getClientPrincipal()} 为包级私有)。
 *
 * @see ClientUserPolicyService
 */
@Slf4j
public final class PolicyAwareRefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private final OAuth2RefreshTokenAuthenticationProvider delegate;
    private final ClientUserPolicyService policyService;
    private final OAuth2AuthorizationService authorizationService;

    public PolicyAwareRefreshTokenAuthenticationProvider(OAuth2RefreshTokenAuthenticationProvider delegate,
            ClientUserPolicyService policyService, OAuth2AuthorizationService authorizationService) {
        this.delegate = delegate;
        this.policyService = policyService;
        this.authorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2RefreshTokenAuthenticationToken refreshAuth = (OAuth2RefreshTokenAuthenticationToken) authentication;
        if (refreshAuth.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal) {
            OAuth2Authorization authorization = authorizationService.findByToken(
                    refreshAuth.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
            if (authorization != null) {
                policyService.check(clientPrincipal.getRegisteredClient(), authorization.getPrincipalName());
            }
        }
        return delegate.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }
}