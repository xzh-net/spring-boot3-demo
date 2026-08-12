package net.xzh.authserver.controller.api;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.JdbcRegisteredClientRepository;

/**
 * 公开客户端列表 API.
 * <p>
 * 提供给 iam-portal-service (BFF) 调用的公开接口, 返回所有可用的 OAuth2 客户端列表
 * (排除 portal-app 自身), 用于门户页面展示 SSO 跳转卡片。
 * <p>
 * 该接口无需认证, 因为门户本身已通过 OAuth2 登录。
 * <p>
 * 三类客户端的跳转策略:
 * <ul>
 *   <li>Confidential Web 客户端 (web-app): 直接生成授权 URL, 实现门户→客户端 SSO</li>
 *   <li>PKCE 公共客户端 (mobile-app): 链接到客户端首页, 客户端自行发起 PKCE 流程
 *       (门户无法代生成 code_challenge, 因为 code_verifier 只有客户端知道)</li>
 * </ul>
 * <p>
 * 设备码客户端 (device-app) 不在门户应用列表中展示, 因为其登录流程由设备端自行发起,
 * 门户无法代为跳转。
 */
@Slf4j
@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicClientController {

    private final JdbcRegisteredClientRepository clientRepository;

    @Value("${auth-server.issuer:http://localhost:9000}")
    private String issuer;

    /**
     * 获取可用客户端列表.
     */
    @GetMapping("/clients")
    public Map<String, Object> listPublicClients() {
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> clients = new ArrayList<>();

        try {
            List<RegisteredClient> allClients = clientRepository.findAll();
            for (RegisteredClient client : allClients) {
                // 跳过门户自身（portal-app）
                if ("portal-app".equals(client.getClientId())) {
                    continue;
                }

                // 设备码客户端不在门户列表中展示 (设备码流程由设备端自行发起)
                boolean isDeviceClient = client.getAuthorizationGrantTypes().stream()
                        .anyMatch(g -> g.getValue().equals(AuthorizationGrantType.DEVICE_CODE.getValue()));
                if (isDeviceClient) {
                    continue;
                }

                // 只返回支持授权码模式的客户端
                if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                    clients.add(buildWebClientItem(client));
                }
            }
            result.put("success", true);
            result.put("clients", clients);
        } catch (Exception e) {
            log.error("[PublicClientController] 获取客户端列表失败", e);
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("clients", clients);
        }
        return result;
    }

    /**
     * 构建 Web 应用客户端项（授权码模式）.
     * <p>
     * 统一策略（无论是否 PKCE）：先跳客户端首页，由客户端自行检测本地 session。
     * 这样做的原因：
     * <ul>
     *   <li>Confidential 客户端如果门户直接生成授权 URL，会绕开客户端自己的 session 检测，
     *       导致用户已在客户端登录后，每次从门户跳转都会重新走完整授权码流程，
     *       签发全新的 access_token / refresh_token，在线管理页出现重复会话。</li>
     *   <li>跳首页后客户端 renderHome() 会判断：已有 session → 直接显示已登录页（不发新 token）；
     *       无 session → 客户端自己再发起 /oauth2/authorize 授权流程。</li>
     *   <li>PKCE 客户端本来就无法由门户代生成 code_challenge，只能跳首页。</li>
     * </ul>
     * <p>
     * redirect_uri 优先选择 localhost (而非 127.0.0.1), 确保与客户端
     * token 交换时提交的 redirect_uri 一致, 避免 invalid_grant 错误.
     */
    private Map<String, Object> buildWebClientItem(RegisteredClient client) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("clientId", client.getClientId());
        item.put("clientName", client.getClientName() != null ? client.getClientName() : client.getClientId());
        item.put("type", "web");

        // 优先选择 localhost 的 redirect_uri
        String redirectUri = client.getRedirectUris().stream()
                .filter(uri -> uri.contains("localhost"))
                .findFirst()
                .orElse(client.getRedirectUris().isEmpty() ? "" : client.getRedirectUris().iterator().next());
        item.put("redirectUri", redirectUri);

        boolean requireProofKey = client.getClientSettings().isRequireProofKey();
        // 统一跳客户端首页，让客户端自己决定是否需要发起授权
        String homeUrl = extractHomeUrl(redirectUri);
        item.put("authorizationUrl", homeUrl != null ? homeUrl : "#");
        if (requireProofKey) {
            item.put("pkce", true);
        }
        item.put("icon", getIcon(client.getClientId()));
        item.put("description", getDescription(client.getClientId()));
        return item;
    }

    /**
     * 从 redirect_uri 提取客户端首页 URL.
     * <p>
     * 例: "http://localhost:8083/callback" → "http://localhost:8083/"
     * 仅处理 http/https 协议, 忽略自定义 scheme (如 com.example.app://).
     */
    private String extractHomeUrl(String redirectUri) {
        try {
            URI uri = new URI(redirectUri);
            if ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme())) {
                return uri.getScheme() + "://" + uri.getAuthority() + "/";
            }
        } catch (Exception e) {
            log.warn("[PublicClientController] 解析 redirectUri 失败: {}", redirectUri, e);
        }
        return null;
    }

    private String getIcon(String clientId) {
        return switch (clientId) {
            case "web-app" -> "📋";
            case "mobile-app" -> "📱";
            case "service-app" -> "⚙️";
            default -> "🔗";
        };
    }

    private String getDescription(String clientId) {
        return switch (clientId) {
            case "web-app" -> "Web应用客户端演示 (授权码模式, SSO直跳)";
            case "mobile-app" -> "移动应用/SPA客户端演示 (PKCE, 点击后自动登录)";
            case "service-app" -> "服务间调用客户端";
            default -> "第三方业务系统";
        };
    }
}
