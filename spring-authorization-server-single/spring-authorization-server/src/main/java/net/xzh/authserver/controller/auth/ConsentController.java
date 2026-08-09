package net.xzh.authserver.controller.auth;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;

    public ConsentController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping("/consent")
    public String consentPage(
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "user_code", required = false) String userCode,
            Model model) {

        String effectiveRedirectUri = redirectUri;
        if (effectiveRedirectUri == null || effectiveRedirectUri.isBlank()) {
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client != null && !client.getRedirectUris().isEmpty()) {
                effectiveRedirectUri = client.getRedirectUris().iterator().next();
            }
        }

        Map<String, String> scopeMap = new LinkedHashMap<>();
        if (scope != null && !scope.isBlank()) {
            for (String s : scope.split("\\s+")) {
                scopeMap.put(s, describeScope(s));
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", clientId);
        model.addAttribute("redirectUri", effectiveRedirectUri);
        model.addAttribute("responseType", responseType != null ? responseType : "code");
        model.addAttribute("scopes", scopeMap);
        model.addAttribute("scopeList", scopeMap.keySet());
        model.addAttribute("state", state);
        model.addAttribute("userCode", userCode);
        // 设备码流程表单提交到 /oauth2/device/verify, 授权码流程提交到 /oauth2/authorize
        model.addAttribute("requestURI",
                (userCode != null && !userCode.isBlank()) ? "/oauth2/device/verify" : "/oauth2/authorize");

        return "consent";
    }

    private String describeScope(String scope) {
        return switch (scope) {
            case "openid" -> "身份认证";
            case "profile" -> "基本资料（姓名、头像等）";
            case "email" -> "电子邮箱";
            case "read" -> "读取权限";
            case "write" -> "写入权限";
            default -> scope;
        };
    }
}
