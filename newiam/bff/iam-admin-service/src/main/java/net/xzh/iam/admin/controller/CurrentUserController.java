package net.xzh.iam.admin.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 当前登录用户信息 (管理后台顶部用户栏调用).
 */
@RestController
@RequestMapping("/api")
public class CurrentUserController {

    @GetMapping("/current-user")
    public Map<String, Object> currentUser(Authentication authentication) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser oidcUser)) {
            result.put("authenticated", false);
            return result;
        }
        result.put("authenticated", true);
        result.put("username", oidcUser.getName());
        result.put("nickname", oidcUser.getAttribute("nickname"));
        result.put("email", oidcUser.getAttribute("email"));
        result.put("roles", oidcUser.getAttribute("roles"));
        result.put("authorities", authentication.getAuthorities().stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toList()));
        return result;
    }
}