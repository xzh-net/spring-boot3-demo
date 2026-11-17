package net.xzh.iam.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.LinkedHashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.LoginAdmissionService;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final LoginAdmissionService loginAdmissionService;

    /** SavedRequest 缓存 — 拒绝时存下原始请求, 使重新登录后能回到同意页重新判定 (语义同 DeviceActivateController) */
    private static final HttpSessionRequestCache REQUEST_CACHE = new HttpSessionRequestCache();

    @GetMapping("/consent")
    public String consentPage(
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "user_code", required = false) String userCode,
            Authentication auth,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // 【登录准入·兜底】防止直接构造 consent URL 绕过 /activate 的前置判定。
        // 与 DeviceActivateController 同判据 (client_login_policy), 同文案踢回登录页。
        if (auth != null && auth.isAuthenticated()
                && !loginAdmissionService.canLogin(clientId, auth.getName())) {
            log.info("[签发准入] 同意页拒绝 (准入表未命中): 客户端={}, 用户={}", clientId, auth.getName());
            // 存 SavedRequest: 否则重新登录后无恢复点, 会走 defaultSuccessUrl "/" → 门户页
            REQUEST_CACHE.saveRequest(request, response);
            return "redirect:/login.html?error=access_denied";
        }

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
