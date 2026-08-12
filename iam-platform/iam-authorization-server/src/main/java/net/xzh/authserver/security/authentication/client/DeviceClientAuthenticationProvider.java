package net.xzh.authserver.security.authentication.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * 设备码流程专用客户端认证提供者.
 * <p>
 * 职责：
 * 1. 验证由 DeviceClientAuthenticationConverter 生成的 OAuth2ClientAuthenticationToken。
 * 2. 检查 client_id 是否存在于 RegisteredClientRepository 中。
 * 3. 确认该客户端被配置为允许使用 NONE 认证方法（即公共客户端）。
 * 4. 返回已认证的 OAuth2ClientAuthenticationToken，携带完整的 RegisteredClient 信息。
 *
 * 架构定位：
 * 属于认证层（authentication/），处理纯逻辑验证，不涉及 HTTP 请求解析。
 * 接收 Converter 输出的未认证 Token，验证后输出已认证 Token。
 *
 * 关键约束：
 * 必须使用 SAS 原生的 OAuth2ClientAuthenticationToken，不能使用自定义子类。
 * 下游 Grant 处理器（如 OAuth2RefreshTokenAuthenticationConverter）依赖严格的
 * 类型检查进行路由，自定义子类会导致 invalid_grant 错误。
 */
public final class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    /** RFC 6749 Section 3.2.1 — 客户端认证失败的错误文档 URI */
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final Log logger = LogFactory.getLog(getClass());

    /** 客户端配置持久化仓库，用于根据 client_id 查询 RegisteredClient */
    private final RegisteredClientRepository registeredClientRepository;

    public DeviceClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 转换为预期的 Token 类型（由 DeviceClientAuthenticationConverter 创建）
        OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;

        // 仅处理认证方法为 NONE 的请求（公共客户端，无密钥）
        // 返回 null 表示本 Provider 不处理，交由 AuthenticationManager 中其他 Provider 尝试
        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }

        String clientId = clientAuthentication.getPrincipal().toString();

        // 1. 根据 client_id 查找 RegisteredClient（必须存在）
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        // 2. 验证客户端是否被允许使用 NONE 认证方法
        // 防止机密客户端（client_secret）意外以公共客户端方式请求
        if (!registeredClient.getClientAuthenticationMethods().contains(
                clientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated device client authentication parameters");
            this.logger.trace("Authenticated device client");
        }

        // 3. 返回已认证的 Token
        // 用从数据库查到的完整 registeredClient 替换原始请求中的 client_id，
        // 使下游 Provider 能获取到客户端配置（grantTypes、scopes 等）
        return new OAuth2ClientAuthenticationToken(
                registeredClient, clientAuthentication.getClientAuthenticationMethod(), null);
    }

    /**
     * 判断本 Provider 是否支持给定的 Authentication 类型。
     * 支持所有 OAuth2ClientAuthenticationToken 实例（其子类也可匹配）。
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * 抛出 invalid_client 类型的 OAuth2AuthenticationException。
     * 用于客户端不存在或认证方法不匹配的场景。
     *
     * @param parameterName 出错的参数名称，用于构造错误描述
     */
    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Device client authentication failed: " + parameterName,
                ERROR_URI);
        throw new OAuth2AuthenticationException(error);
    }
}