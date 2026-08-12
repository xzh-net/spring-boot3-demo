package net.xzh.authserver.controller.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class UserInfoController {

    private final OpaqueTokenIntrospector introspector;

    public UserInfoController(OpaqueTokenIntrospector introspector) {
        this.introspector = introspector;
    }

    @GetMapping("/userinfo")
    public Map<String, Object> getUserInfo(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        return buildUserInfo(authorization);
    }

    @PostMapping("/userinfo")
    public Map<String, Object> postUserInfo(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        return buildUserInfo(authorization);
    }

    private Map<String, Object> buildUserInfo(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            OAuth2ErrorCodes.INVALID_TOKEN,
                            "Missing or invalid Authorization header",
                            null));
        }
        String token = authorization.substring("Bearer ".length());
        OAuth2AuthenticatedPrincipal principal = introspector.introspect(token);

        Map<String, Object> result = new LinkedHashMap<>();
        Map<String, Object> attrs = principal.getAttributes();
        result.put("sub", principal.getName());

        String scope = (String) attrs.get("scope");
        if (scope != null) {
            for (String s : scope.split(" ")) {
                switch (s) {
                    case "profile" -> {
                        result.put("preferred_username", principal.getName());
                        result.put("updated_at", attrs.get("exp"));
                    }
                    case "email" -> {
                        result.put("email", principal.getName() + "@example.com");
                        result.put("email_verified", true);
                    }
                    case "openid" -> { /* sub 已添加 */ }
                    default -> { /* 不识别的 scope 跳过 */ }
                }
            }
        }
        return result;
    }
}
