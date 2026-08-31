package net.xzh.iam.portal.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 资源服务 API 客户端.
 * <p>
 * 调用资源服务 (iam-resource-service:9010) 门户端公开接口:
 * <p>
 * 当前人员可见客户端列表 {@code GET /api/public/clients/mine} (携带用户 Bearer Token,
 * 由资源中心按应用授权过滤)。客户端列表接口已从认证中心迁移至资源服务, 本类与认证中心无直接调用关系。
 * </p>
 */
@Slf4j
@Component
public class AuthServerClient {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Value("${resource-server.base-url}")
    private String baseUrl;

    @Value("${resource-server.mine-clients-api}")
    private String mineClientsApi;

    /**
     * 获取当前人员可见客户端列表.
     * <p>
     * 携带当前登录用户 (portal-app) 的 Access Token 调用资源服务
     * {@code GET /api/public/clients/mine}, 由资源中心按应用授权 (visible / iam_app_authorization)
     * 过滤出该用户可见的应用/渠道卡片。
     * </p>
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listMyClients(String accessToken) throws Exception {
        return requestClients(baseUrl + mineClientsApi, accessToken);
    }

    /** 请求统一 Result 包装: {code, msg, data, timestamp}, data 为客户端数组 */
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> requestClients(String url, String accessToken) throws Exception {
        log.debug("[AuthServerClient] 调用资源服务获取客户端列表: {}", url);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(10));
        if (accessToken != null && !accessToken.isBlank()) {
            builder.header("Authorization", "Bearer " + accessToken);
        }
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            log.error("[AuthServerClient] 获取客户端列表失败: HTTP {} - {}", response.statusCode(), response.body());
            return Collections.emptyList();
        }

        Map<String, Object> body = objectMapper.readValue(response.body(),
                new TypeReference<Map<String, Object>>() {});

        // Result 包装: data 为客户端数组
        Object data = body.get("data");
        if (data instanceof List) {
            return (List<Map<String, Object>>) data;
        }
        return Collections.emptyList();
    }
}
