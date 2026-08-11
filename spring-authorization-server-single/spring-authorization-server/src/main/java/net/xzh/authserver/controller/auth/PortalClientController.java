package net.xzh.authserver.controller.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.xzh.authserver.security.repository.JdbcRegisteredClientRepository;

/**
 * 门户客户端列表控制器.
 * <p>
 * 提供门户页面的客户端应用列表，动态生成 OAuth2 授权链接，
 * 实现门户 → 客户端的 SSO 自动跳转。
 */
@RestController
@RequestMapping("/portal-api")
@RequiredArgsConstructor
public class PortalClientController {

    private final JdbcRegisteredClientRepository clientRepository;

    /**
     * 获取门户可用的客户端列表.
     * <p>
     * 包含两类应用：
     * 1. Web应用（支持authorization_code）- 直接跳转SSO
     * 2. 设备码应用（支持device_code）- 跳转到设备授权页面
     */
    @GetMapping("/clients")
    public List<Map<String, Object>> listPortalClients() {
        List<Map<String, Object>> result = new ArrayList<>();
        List<RegisteredClient> allClients = clientRepository.findAll();

        for (RegisteredClient client : allClients) {
            // 跳过门户自身（portal-app）
            if ("portal-app".equals(client.getClientId())) {
                continue;
            }

            boolean isDeviceClient = client.getClientAuthenticationMethods().stream()
                    .anyMatch(m -> m.getValue().equals("none"));

            if (isDeviceClient) {
                // 设备码客户端：生成设备授权链接
                result.add(buildDeviceClientItem(client));
            } else if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                // Web应用客户端：生成授权码链接
                result.add(buildWebClientItem(client));
            }
        }
        return result;
    }

    /**
     * 构建Web应用客户端项（授权码模式）.
     */
    private Map<String, Object> buildWebClientItem(RegisteredClient client) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("clientId", client.getClientId());
        item.put("clientName", client.getClientName() != null ? client.getClientName() : client.getClientId());
        item.put("type", "web");

        String redirectUri = client.getRedirectUris().isEmpty() ? "" : client.getRedirectUris().iterator().next();
        item.put("redirectUri", redirectUri);

        String state = UUID.randomUUID().toString();
        item.put("state", state);

        String scope = String.join(" ", client.getScopes());
        String authUrl = "/oauth2/authorize"
                + "?response_type=code"
                + "&client_id=" + client.getClientId()
                + "&redirect_uri=" + redirectUri
                + "&scope=" + scope
                + "&state=" + state;
        item.put("authUrl", authUrl);
        item.put("icon", getIcon(client.getClientId()));
        item.put("description", getDescription(client.getClientId()));
        return item;
    }

    /**
     * 构建设备码客户端项（设备码模式）.
     */
    private Map<String, Object> buildDeviceClientItem(RegisteredClient client) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("clientId", client.getClientId());
        item.put("clientName", client.getClientName() != null ? client.getClientName() : client.getClientId());
        item.put("type", "device");
        item.put("icon", getDeviceIcon(client.getClientId()));
        item.put("description", getDeviceDescription(client.getClientId()));
        
        String scope = String.join(" ", client.getScopes());
        item.put("scope", scope);
        
        return item;
    }

    private String getIcon(String clientId) {
        return switch (clientId) {
            case "web-app" -> "📋";
            case "mobile-app" -> "📱";
            case "service-app" -> "⚙️";
            default -> "🔗";
        };
    }

    private String getDeviceIcon(String clientId) {
        return switch (clientId) {
            case "device-app" -> "📺";
            case "tv-app" -> "📺";
            case "iot-app" -> "🔌";
            default -> "📱";
        };
    }

    /**
     * 生成客户端→门户的SSO授权URL。
     */
    @GetMapping("/portal-sso-url")
    public Map<String, String> getPortalSsoUrl(
            @RequestParam(value = "currentClientId", required = false) String currentClientId) {
        Map<String, String> result = new LinkedHashMap<>();
        try {
            RegisteredClient portalClient = clientRepository.findByClientId("portal-app");
            if (portalClient == null) {
                result.put("error", "portal-app client not configured");
                return result;
            }

            String redirectUri = "http://localhost:9000/portal.html";
            String state = UUID.randomUUID().toString();
            String scope = String.join(" ", portalClient.getScopes());

            String authUrl = "/oauth2/authorize"
                    + "?response_type=code"
                    + "&client_id=portal-app"
                    + "&redirect_uri=" + redirectUri
                    + "&scope=" + scope
                    + "&state=" + state;

            result.put("authUrl", authUrl);
            result.put("clientId", "portal-app");
            result.put("redirectUri", redirectUri);
            result.put("state", state);
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    private String getDescription(String clientId) {
        return switch (clientId) {
            case "web-app" -> "Web应用客户端演示";
            case "mobile-app" -> "移动应用/SPA客户端演示";
            case "service-app" -> "服务间调用客户端";
            default -> "第三方业务系统";
        };
    }

    /**
     * 发起设备码授权流程.
     * <p>
     * 为指定的设备码客户端获取device_code和user_code，返回授权链接。
     * 用户点击后可直接跳转到授权确认页面，实现SSO体验。
     */
    @GetMapping("/device-auth")
    public Map<String, Object> initiateDeviceAuth(
            @RequestParam("clientId") String clientId) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            RegisteredClient client = clientRepository.findByClientId(clientId);
            if (client == null) {
                result.put("error", "客户端不存在");
                return result;
            }

            // 构建设备码授权请求
            String scope = String.join(" ", client.getScopes());
            
            // 构建请求参数
            String params = "client_id=" + clientId + "&scope=" + java.net.URLEncoder.encode(scope, "UTF-8");
            
            // 调用设备码授权端点
            String response = sendHttpRequest(
                    "http://localhost:9000/oauth2/device_authorization",
                    "POST", params, false);

            com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Map<String, Object> deviceCodeData = objectMapper.readValue(response,
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});

            result.put("success", true);
            result.put("deviceCode", deviceCodeData.get("device_code"));
            result.put("userCode", deviceCodeData.get("user_code"));
            result.put("verificationUri", deviceCodeData.get("verification_uri"));
            result.put("verificationUriComplete", deviceCodeData.get("verification_uri_complete"));
            result.put("expiresIn", deviceCodeData.get("expires_in"));

        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        return result;
    }

    /**
     * 发送HTTP请求.
     */
    private String sendHttpRequest(String url, String method, String body, boolean withAuth) throws Exception {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(10000);

        if (body != null && !body.isEmpty()) {
            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes("UTF-8"));
            }
        }

        int responseCode = conn.getResponseCode();
        java.io.InputStream is = responseCode >= 200 && responseCode < 300
                ? conn.getInputStream()
                : conn.getErrorStream();

        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(is, "UTF-8"))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        } finally {
            conn.disconnect();
        }
    }

    private String getDeviceDescription(String clientId) {
        return switch (clientId) {
            case "device-app" -> "设备码授权（智能电视/IoT等无浏览器设备）";
            case "tv-app" -> "电视应用设备码登录";
            case "iot-app" -> "IoT设备授权";
            default -> "无浏览器设备授权";
        };
    }
}
