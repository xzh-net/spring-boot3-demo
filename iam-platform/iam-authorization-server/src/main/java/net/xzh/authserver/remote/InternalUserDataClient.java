package net.xzh.authserver.remote;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.config.AuthServerProperties;

/**
 * 资源中心远程用户数据清理 (删除 sys_user 时联动).
 * <p>
 * 认证中心删除用户后, 调用资源中心管理端能力
 * {@code DELETE /api/admin/users/{userCode}/data}, 清理该用户 (user_code)
 * 在资源中心的跨库孤儿数据: {@code sys_user_role} 角色绑定 +
 * {@code iam_app_authorization} USER 主体应用授权。
 * 该调用以<b>管理 M2M 服务凭证</b> (admin-m2m 客户端 client_credentials, 经
 * {@link ServiceTokenProvider#getAdminToken()}) 发起, 资源中心内省时注入
 * ADMIN_SERVICE_TOKEN (管理服务凭证); 401 时与服务凭证失效自愈。
 * </p>
 */
@Slf4j
@Component
public class InternalUserDataClient {

    private final AuthServerProperties properties;
    private final ServiceTokenProvider serviceTokenProvider;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public InternalUserDataClient(AuthServerProperties properties,
                                  ServiceTokenProvider serviceTokenProvider,
                                  ObjectMapper objectMapper) {
        this.properties = properties;
        this.serviceTokenProvider = serviceTokenProvider;
        this.objectMapper = objectMapper;
    }

    /**
     * 删除用户在资源中心的全部关联数据.
     *
     * @param userCode 业务用户编码
     * @throws IllegalStateException 资源中心不可达或响应异常
     */
    public void deleteUserData(String userCode) {
        String url = properties.getResourceServiceBaseUrl()
                + "/api/admin/users/" + encode(userCode) + "/data";
        try {
            HttpResponse<String> resp = sendDelete(url, serviceTokenProvider.getAdminToken());
            if (resp.statusCode() == 401) {
                log.warn("[UserData] 清理接口返回 HTTP 401, 判定管理 M2M 凭证已失效, 强制刷新后重试一次. userCode={}", userCode);
                serviceTokenProvider.invalidateAdminToken();
                resp = sendDelete(url, serviceTokenProvider.getAdminToken());
            }
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("清理用户关联接口返回 HTTP " + resp.statusCode());
            }
            JsonNode root = objectMapper.readTree(resp.body());
            int code = root.path("code").asInt();
            if (code != 200) {
                throw new IllegalStateException("清理用户关联接口业务码 " + code + ": " + root.path("msg").asText());
            }
            log.info("[UserData] 已清理资源中心用户关联 userCode={}, deleted={}",
                    userCode, root.path("data"));
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("调用资源中心清理用户关联接口失败 userCode=" + userCode + ": " + e.getMessage(), e);
        }
    }

    private HttpResponse<String> sendDelete(String url, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(5))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json")
                .DELETE()
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}