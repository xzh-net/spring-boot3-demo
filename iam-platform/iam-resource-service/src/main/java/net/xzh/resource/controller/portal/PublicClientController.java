package net.xzh.resource.controller.portal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.config.AuthServerProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 公开客户端列表 API（资源中心 portal 端能力域，门户应用 / SSO 跳转所需目录）.
 * <p>
 * 门户（iam-portal-web/service）经此接口拉取可跳转客户端做 SSO 卡片；
 * 当前路径 /api/public/clients 为 permitAll，portal 端与公开端均可用。
 * <p>
 * V6 定版：oauth2_registered_client 仅存于 iam_identity (认证中心)，
 * 本中心不再直读该表，改以 client_credentials 服务令牌调用
 * 认证中心 {@code GET /api/directory/clients} 获取客户端目录。
 * 结果带 60s 本地缓存，避免高频公共请求直接打到认证中心。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicClientController {

    private final AuthServerProperties authServer;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    /** 目录缓存 (60s TTL), value = 目录 JSON data 数组 */
    private volatile CachedDirectory cached;

    /**
     * 返回可供门户跳转的客户端列表 (透传认证中心目录 API 结果).
     */
    @GetMapping("/clients")
    public Result<List<Map<String, Object>>> clients() {
        try {
            JsonNode data = directory();
            List<Map<String, Object>> result = new ArrayList<>();
            if (data != null && data.isArray()) {
                for (JsonNode node : data) {
                    Map<String, Object> item = objectMapper.convertValue(node, Map.class);
                    result.add(item);
                }
            }
            return Result.ok(result);
        } catch (Exception e) {
            log.warn("[PublicClientController] 拉取客户端目录失败: {}", e.getMessage());
            return Result.fail("客户端目录暂不可用");
        }
    }

    // ------------------------------------------------------------------
    // 目录获取: 60s 本地缓存 + client_credentials 换取服务令牌
    // ------------------------------------------------------------------

    private JsonNode directory() throws Exception {
        CachedDirectory c = cached;
        long now = System.currentTimeMillis();
        if (c != null && now < c.expireAt) {
            return c.data;
        }
        synchronized (this) {
            c = cached;
            now = System.currentTimeMillis();
            if (c != null && now < c.expireAt) {
                return c.data;
            }
            String accessToken = fetchServiceToken();
            JsonNode data = fetchDirectory(accessToken);
            cached = new CachedDirectory(data, now + 60_000L);
            return data;
        }
    }

    /** 使用 client_credentials 授权向认证中心换取服务令牌 */
    private String fetchServiceToken() throws Exception {
        String body = "grant_type=client_credentials"
                + "&client_id=" + enc(authServer.getClientId())
                + "&client_secret=" + enc(authServer.getClientSecret())
                + "&scope=read";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(authServer.getBaseUrl() + "/oauth2/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("令牌端点返回 " + response.statusCode());
        }
        JsonNode json = objectMapper.readTree(response.body());
        String token = json.path("access_token").asText(null);
        if (token == null) {
            throw new IllegalStateException("令牌端点未返回 access_token");
        }
        return token;
    }

    /** 调用认证中心目录 API */
    private JsonNode fetchDirectory(String accessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(authServer.getBaseUrl() + "/api/directory/clients"))
                .header("Authorization", "Bearer " + accessToken)
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("目录接口返回 " + response.statusCode());
        }
        JsonNode json = objectMapper.readTree(response.body());
        return json.path("data");
    }

    private static String enc(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    /** 简单的 60s 失效缓存条目 */
    private static final class CachedDirectory {
        final JsonNode data;
        final long expireAt;

        CachedDirectory(JsonNode data, long expireAt) {
            this.data = data;
            this.expireAt = expireAt;
        }
    }
}