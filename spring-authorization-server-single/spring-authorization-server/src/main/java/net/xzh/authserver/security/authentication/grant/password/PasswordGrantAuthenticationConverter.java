package net.xzh.authserver.security.authentication.grant.password;

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

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter("grant_type");
        if (!PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (clientPrincipal == null || !(clientPrincipal instanceof OAuth2ClientAuthenticationToken)) {
            return null;
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            return null;
        }

        Set<String> scopes = new HashSet<>();
        String scopeParam = request.getParameter("scope");
        if (StringUtils.hasText(scopeParam)) {
            scopes.addAll(Arrays.asList(scopeParam.trim().split("\\s+")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (values.length > 0 && !isStandardParam(key)) {
                additionalParameters.put(key, values[0]);
            }
        });

        return new PasswordGrantAuthenticationToken(clientPrincipal, username, password, scopes, additionalParameters);
    }

    private boolean isStandardParam(String key) {
        Set<String> standard = Set.of(
                "grant_type", "username", "password", "scope",
                "client_id", "client_secret", "code", "redirect_uri",
                "state", "code_verifier", "code_challenge", "code_challenge_method"
        );
        return standard.contains(key);
    }
}
