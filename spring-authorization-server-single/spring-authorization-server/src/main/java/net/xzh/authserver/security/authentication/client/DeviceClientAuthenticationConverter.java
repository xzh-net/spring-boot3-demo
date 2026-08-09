package net.xzh.authserver.security.authentication.client;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * 设备码 public client 认证转换器.
 * <p>
 * 从以下请求中提取 client_id 参数, 构造 {@link OAuth2ClientAuthenticationToken}:
 * <ul>
 *   <li>设备码授权请求 (POST /oauth2/device_authorization)</li>
 *   <li>设备码 token 轮询请求 (POST /oauth2/token?grant_type=device_code)</li>
 *   <li>刷新 token 请求 (POST /oauth2/token?grant_type=refresh_token)</li>
 * </ul>
 * 返回 OAuth2ClientAuthenticationToken (而非 DeviceClientAuthenticationToken),
 * 因为 SAS 下游所有 token converter (refresh_token, device_code, authorization_code 等)
 * 都检查 SecurityContext 中的 OAuth2ClientAuthenticationToken 类型.
 * <p>
 * 参考: SAS 官方示例 sample.web.authentication.DeviceClientAuthenticationConverter
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {
    private final RequestMatcher deviceAuthorizationRequestMatcher;
    private final RequestMatcher deviceAccessTokenRequestMatcher;
    private final RequestMatcher introspectRequestMatcher;
    private final RequestMatcher revokeRequestMatcher;

    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri) {
        RequestMatcher clientIdParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
        this.deviceAuthorizationRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(
                        deviceAuthorizationEndpointUri, HttpMethod.POST.name()),
                clientIdParameterMatcher);
        // public client (NONE) 无 client_secret, 需通过 client_id 参数认证.
        // 同时匹配 device_code 和 refresh_token 两种 grant_type:
        //   - device_code: 设备码轮询取 token
        //   - refresh_token: 用 refresh_token 换新 token
        // 若不匹配 refresh_token, 刷新请求无 converter 处理 → 客户端未认证 → invalid_grant
        this.deviceAccessTokenRequestMatcher = request -> {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            boolean isDeviceCodeGrant = AuthorizationGrantType.DEVICE_CODE.getValue().equals(grantType)
                    && request.getParameter(OAuth2ParameterNames.DEVICE_CODE) != null;
            boolean isRefreshTokenGrant = AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)
                    && request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN) != null;
            return (isDeviceCodeGrant || isRefreshTokenGrant)
                    && request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;
        };
        this.introspectRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher("/oauth2/introspect", HttpMethod.POST.name()),
                clientIdParameterMatcher);
        this.revokeRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher("/oauth2/revoke", HttpMethod.POST.name()),
                clientIdParameterMatcher);
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!this.deviceAuthorizationRequestMatcher.matches(request) &&
                !this.deviceAccessTokenRequestMatcher.matches(request) &&
                !this.introspectRequestMatcher.matches(request) &&
                !this.revokeRequestMatcher.matches(request)) {
            return null;
        }

        // client_id (REQUIRED)
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId) ||
                request.getParameterValues(OAuth2ParameterNames.CLIENT_ID).length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // 返回 OAuth2ClientAuthenticationToken (而非 DeviceClientAuthenticationToken),
        // 使 SAS 下游 token converter 能正确识别已认证 client
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, null);
    }
}
