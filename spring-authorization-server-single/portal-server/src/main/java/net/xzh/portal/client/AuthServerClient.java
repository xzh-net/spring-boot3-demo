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
 * 认证中心 API 客户端.
 * <p>
 * 调用认证中心的公开接口获取客户端列表等信息。
 */
@Slf4j
@Component
public class AuthServerClient {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    @Value("${auth-server.base-url}")
    private String baseUrl;

    @Value("${auth-server.clients-api}")
    private String clientsApi;

    /**
     * 获取认证中心的公开客户端列表.
     * <p>
     * 调用 GET /api/public/clients 接口，返回所有可用的 OAuth2 客户端
     * (排除 portal-app 自身)。
     */
    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listPublicClients() throws Exception {
        String url = baseUrl + clientsApi;
        log.debug("[AuthServerClient] 调用认证中心获取客户端列表: {}", url);

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

        Object clients = body.get("clients");
        if (clients instanceof List) {
            return (List<Map<String, Object>>) clients;
        }
        return Collections.emptyList();
    }
}
