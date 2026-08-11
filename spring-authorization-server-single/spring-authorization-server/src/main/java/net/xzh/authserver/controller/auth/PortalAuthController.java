package net.xzh.authserver.controller.auth;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.DataInitializer;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 门户认证控制器.
 * <p>
 * 提供门户相关的认证API，包括token交换等功能。
 * 由于门户和认证中心在同一个服务中，使用后端代理方式保证安全性。
 */
@Slf4j
@RestController
@RequestMapping("/api/portal")
public class PortalAuthController {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 使用授权码换取token（后端代理）.
     */
    @PostMapping("/token")
    public Map<String, Object> exchangeToken(
            @RequestParam("code") String code,
            @RequestParam("redirect_uri") String redirectUri) {
        return doTokenExchange("authorization_code", code, redirectUri);
    }

    /**
     * 刷新token（后端代理）.
     */
    @PostMapping("/refresh")
    public Map<String, Object> refreshToken(
            @RequestParam("refresh_token") String refreshToken) {
        return doTokenExchange("refresh_token", refreshToken, null);
    }

    /**
     * 吊销token.
     */
    @PostMapping("/revoke")
    public Map<String, Object> revokeToken(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint) {

        Map<String, Object> result = new LinkedHashMap<>();

        try {
            StringBuilder params = new StringBuilder();
            params.append("token=").append(token);
            if (tokenTypeHint != null) {
                params.append("&token_type_hint=").append(tokenTypeHint);
            }

            String response = sendHttpRequest("http://localhost:9000/oauth2/revoke", 
                    "POST", params.toString(), true);

            result.put("success", true);
            log.info("[PortalAuth] Token吊销成功");

        } catch (Exception e) {
            log.error("[PortalAuth] Token吊销失败", e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }

        return result;
    }

    /**
     * 执行token交换.
     */
    private Map<String, Object> doTokenExchange(String grantType, String codeOrToken, String redirectUri) {
        Map<String, Object> result = new LinkedHashMap<>();

        try {
            StringBuilder params = new StringBuilder();
            params.append("grant_type=").append(grantType);
            
            if ("authorization_code".equals(grantType)) {
                params.append("&code=").append(codeOrToken);
                params.append("&redirect_uri=").append(redirectUri);
            } else if ("refresh_token".equals(grantType)) {
                params.append("&refresh_token=").append(codeOrToken);
            }
            
            params.append("&client_id=portal-app");

            String response = sendHttpRequest("http://localhost:9000/oauth2/token", 
                    "POST", params.toString(), true);

            Map<String, Object> tokenData = objectMapper.readValue(response, 
                    new TypeReference<Map<String, Object>>() {});

            result.put("success", true);
            result.put("data", tokenData);

            log.info("[PortalAuth] Token交换成功 (grant_type={})", grantType);

        } catch (Exception e) {
            log.error("[PortalAuth] Token交换失败", e);
            result.put("success", false);
            result.put("error", e.getMessage());
        }

        return result;
    }

    /**
     * 发送HTTP请求.
     */
    private String sendHttpRequest(String urlStr, String method, String body, boolean withAuth) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setDoOutput(body != null);
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        if (withAuth) {
            String credentials = "portal-app:" + DataInitializer.getPortalClientSecret();
            String authHeader = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            conn.setRequestProperty("Authorization", authHeader);
        }

        if (body != null) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }

        int responseCode = conn.getResponseCode();
        BufferedReader reader;
        if (responseCode >= 200 && responseCode < 300) {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
        }

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        conn.disconnect();

        if (responseCode >= 200 && responseCode < 300) {
            return response.toString();
        } else {
            throw new RuntimeException("HTTP " + responseCode + ": " + response);
        }
    }
}
