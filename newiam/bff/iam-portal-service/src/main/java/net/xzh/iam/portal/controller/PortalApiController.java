package net.xzh.iam.portal.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.portal.service.AuthServerClient;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 门户 API 控制器.
 * <p>
 * 为 iam-portal-web 前端 (8000) 提供 REST API:
 * <ul>
 *   <li>GET /api/user/me — 获取当前登录用户信息</li>
 *   <li>GET /api/clients — 获取当前人员可见客户端列表 (携带用户 Token 调用资源中心
 *       PublicClientController /api/public/clients/mine, 按应用授权过滤)</li>
 * </ul>
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class PortalApiController {

    private final AuthServerClient authServerClient;

    /**
     * 获取当前登录用户信息.
     * <p>
     * 从 OAuth2/OIDC 登录后的 OidcUser 中提取用户信息返回给前端。
     */
    @GetMapping("/user/me")
    public Map<String, Object> getCurrentUser(@AuthenticationPrincipal OidcUser principal) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (principal == null) {
            result.put("authenticated", false);
            return result;
        }
        result.put("authenticated", true);
        result.put("username", principal.getPreferredUsername() != null
                ? principal.getPreferredUsername()
                : principal.getSubject());
        result.put("subject", principal.getSubject());
        result.put("email", principal.getEmail());
        result.put("fullName", principal.getFullName());
        result.put("claims", principal.getClaims());
        return result;
    }

    /**
     * 获取当前人员可见客户端列表.
     * <p>
     * 携带当前登录用户 (portal-app) 的 Access Token 调用资源中心
     * PublicClientController {@code GET /api/public/clients/mine}, 返回该用户
     * 按应用授权可见的应用/渠道卡片 (SSO 跳转目录)。
     */
    @GetMapping("/clients")
    public Map<String, Object> listClients(
            @RegisteredOAuth2AuthorizedClient("portal-app-oidc") OAuth2AuthorizedClient authorizedClient) {
        Map<String, Object> result = new LinkedHashMap<>();
        String accessToken = (authorizedClient != null && authorizedClient.getAccessToken() != null)
                ? authorizedClient.getAccessToken().getTokenValue()
                : null;
        if (accessToken == null) {
            result.put("success", false);
            result.put("error", "未登录");
            return result;
        }
        try {
            List<Map<String, Object>> clients = authServerClient.listMyClients(accessToken);
            result.put("success", true);
            result.put("clients", clients);
        } catch (Exception e) {
            log.error("[PortalApi] 获取当前人员可见客户端列表失败", e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }
}
