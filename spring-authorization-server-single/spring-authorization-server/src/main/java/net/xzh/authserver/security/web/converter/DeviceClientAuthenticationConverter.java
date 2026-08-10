package net.xzh.authserver.security.web.converter;

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
 * 设备授权流程专用客户端认证转换器.
 * <p>
 * 职责：
 * 1. 识别特定的 OAuth 2.0 端点请求（设备授权、设备码令牌、内省、吊销）。
 * 2. 从请求中提取 client_id。
 * 3. 构建一个未认证的 OAuth2ClientAuthenticationToken，认证方法指定为 NONE（公共客户端）。
 *
 * 架构定位：
 * 属于 Web 层，负责将 HTTP 请求转换为 Spring Security 内部可处理的认证对象，
 * 专门用于处理无法安全存储密钥的设备端应用（公共客户端）。
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    // 匹配设备授权端点 (POST /oauth2/device_authorization)
    private final RequestMatcher deviceAuthorizationRequestMatcher;

    // 匹配设备码令牌请求 (grant_type=device_code 或 refresh_token)
    private final RequestMatcher deviceAccessTokenRequestMatcher;

    // 匹配内省端点 (POST /oauth2/introspect)
    private final RequestMatcher introspectRequestMatcher;

    // 匹配吊销端点 (POST /oauth2/revoke)
    private final RequestMatcher revokeRequestMatcher;

    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri) {
        // 辅助匹配器：检查请求中是否包含 client_id 参数
        RequestMatcher clientIdParameterMatcher = request -> request.getParameter(OAuth2ParameterNames.CLIENT_ID) != null;

        // 1. 设备授权请求匹配器：必须是 POST 请求，路径匹配，且包含 client_id
        this.deviceAuthorizationRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher(deviceAuthorizationEndpointUri, HttpMethod.POST.name()),
                clientIdParameterMatcher);

        // 2. 设备令牌请求匹配器：
        //    必须是 grant_type=urn:ietf:params:oauth:grant-type:device_code (且含 device_code)
        //    或者 grant_type=refresh_token (且含 refresh_token)
        //    并且必须包含 client_id
        this.deviceAccessTokenRequestMatcher = request -> {
            String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
            boolean isDeviceCodeGrant = AuthorizationGrantType.DEVICE_CODE.getValue().equals(grantType)
                    && request.getParameter(OAuth2ParameterNames.DEVICE_CODE) != null;
            boolean isRefreshTokenGrant = AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)
                    && request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN) != null;
            return (isDeviceCodeGrant || isRefreshTokenGrant) && clientIdParameterMatcher.matches(request);
        };

        // 3. 内省请求匹配器：POST /oauth2/introspect 且包含 client_id
        this.introspectRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher("/oauth2/introspect", HttpMethod.POST.name()),
                clientIdParameterMatcher);

        // 4. 吊销请求匹配器：POST /oauth2/revoke 且包含 client_id
        this.revokeRequestMatcher = new AndRequestMatcher(
                new AntPathRequestMatcher("/oauth2/revoke", HttpMethod.POST.name()),
                clientIdParameterMatcher);
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // 如果请求不匹配上述任何一种设备相关的场景，则返回 null，交由其他 Converter 处理
        if (!this.deviceAuthorizationRequestMatcher.matches(request) &&
            !this.deviceAccessTokenRequestMatcher.matches(request) &&
            !this.introspectRequestMatcher.matches(request) &&
            !this.revokeRequestMatcher.matches(request)) {
            return null;
        }

        // 提取 client_id (REQUIRED)
        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

        // 校验 client_id 必须存在且唯一
        if (!StringUtils.hasText(clientId) || request.getParameterValues(OAuth2ParameterNames.CLIENT_ID).length != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // 创建未认证的 Token
        // 注意：这里使用 ClientAuthenticationMethod.NONE，表明这是一个公共客户端（无密钥）
        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null, null);
    }
}