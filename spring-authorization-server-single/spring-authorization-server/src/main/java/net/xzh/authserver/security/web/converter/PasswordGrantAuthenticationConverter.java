package net.xzh.authserver.security.web.converter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;
import net.xzh.authserver.security.authentication.grant.PasswordGrantAuthenticationToken;

/**
 * 密码授权模式专用认证转换器.
 * <p>
 * 职责：
 * 1. 识别 grant_type=password 的令牌请求。
 * 2. 从请求中提取 username、password、scope 参数。
 * 3. 构建一个未认证的 PasswordGrantAuthenticationToken，携带客户端主体和用户凭据。
 *
 * 架构定位：
 * 属于 Web 层，负责将 HTTP 请求转换为 Spring Security 内部可处理的认证对象。
 * 前置条件：请求必须已通过客户端认证（OAuth2ClientAuthenticationToken 存在于 SecurityContext），
 * 本 Converter 仅处理资源所有者凭据的提取与封装。
 */
public final class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // 仅处理 grant_type=password 的请求，其他授权模式交由其他 Converter 处理
        String grantType = request.getParameter("grant_type");
        if (!PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        // 获取已认证的客户端主体
        // 前置条件：客户端必须已通过 OAuth2ClientAuthenticationFilter 认证
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (clientPrincipal == null || !(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            return null;
        }

        // 提取资源所有者凭据 (REQUIRED)
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // username 和 password 必须同时存在
        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            return null;
        }

        // 提取请求的 scope 列表
        Set<String> scopes = new HashSet<>();
        String scopeParam = request.getParameter("scope");
        if (StringUtils.hasText(scopeParam)) {
            scopes.addAll(Arrays.asList(scopeParam.trim().split("\\s+")));
        }

        // 收集非标准参数，透传至 Token 中供后续 Provider 使用
        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (values.length > 0 && !isStandardParam(key)) {
                additionalParameters.put(key, values[0]);
            }
        });

        // 创建未认证的 PasswordGrantAuthenticationToken
        return new PasswordGrantAuthenticationToken(clientPrincipal, username, password, scopes, additionalParameters);
    }

    /**
     * 判断参数是否为 OAuth 2.0 标准参数（不应透传到 additionalParameters 中）。
     */
    private boolean isStandardParam(String key) {
        Set<String> standard = Set.of(
                "grant_type", "username", "password", "scope",
                "client_id", "client_secret", "code", "redirect_uri",
                "state", "code_verifier", "code_challenge", "code_challenge_method"
        );
        return standard.contains(key);
    }
}