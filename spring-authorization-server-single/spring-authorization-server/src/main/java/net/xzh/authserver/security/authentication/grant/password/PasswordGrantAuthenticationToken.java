package net.xzh.authserver.security.authentication.grant.password;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    public static final AuthorizationGrantType PASSWORD = new AuthorizationGrantType("password");

    private final Authentication clientPrincipal;
    private final String username;
    private final String password;
    private final Set<String> scopes;

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

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public Authentication getClientPrincipal() {
        return clientPrincipal;
    }
}
