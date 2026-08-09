package net.xzh.authserver.controller.auth;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal UserDetails user, HttpServletRequest request) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (user != null) {
            result.put("authenticated", true);
            result.put("username", user.getUsername());
            result.put("authorities", user.getAuthorities().stream()
                    .map(a -> a.getAuthority()).toList());
            result.put("sessionId", request.getSession(false) != null ? request.getSession(false).getId() : null);
        } else {
            result.put("authenticated", false);
        }
        return result;
    }
}
