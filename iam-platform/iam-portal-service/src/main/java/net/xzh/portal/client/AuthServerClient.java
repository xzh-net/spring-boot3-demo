package net.xzh.portal.client;

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
 * 调用资源服务 (iam-resource-service:9010) 的公开客户端列表接口，
 * 该接口已从认证中心 (`/api/public/clients`) 迁移至资源服务。
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

    @Value("${resource-server.clients-api}")
    private String clientsApi;

    /**
     * 获取公开客户端列表.
     * <p>
     * 调用资源服务 GET /api/public/clients 接口，返回所有可用的 OAuth2 客户端
     * (排除 portal-app 自身)。响应结构为统一 Result 包装: {@code {code, msg, data, timestamp}}。
     * </p>
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listPublicClients() throws Exception {
        String url = baseUrl + clientsApi;
        log.debug("[AuthServerClient] 调用资源服务获取客户端列表: {}", url);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .timeout(Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

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