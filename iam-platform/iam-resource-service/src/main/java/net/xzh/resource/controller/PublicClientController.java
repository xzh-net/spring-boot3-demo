package net.xzh.resource.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.entity.OAuth2RegisteredClient;
import net.xzh.resource.mapper.OAuth2RegisteredClientMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 公开客户端列表 API (自认证中心迁移).
 * <p>
 * 数据完全来自 MySQL oauth2_registered_client 表 (排除 portal-app 自身)，
 * 链接信息从数据库的 redirect_uris 派生，不再硬编码。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicClientController {

    private final OAuth2RegisteredClientMapper clientMapper;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 返回可供门户跳转的客户端列表.
     * <p>
     * 与旧版认证中心实现保持一致:
     * <ul>
     *   <li>设备码客户端 (device_app) 流程由设备端自行发起, 门户无法代跳, 排除;</li>
     *   <li>仅展示支持授权码模式的客户端 (页面点击可正常跳转);</li>
     *   <li>homepage 从数据库 redirect_uris 提取 (优先 localhost, 仅 http/https);</li>
     *   <li>PKCE 客户端额外标记 pkce=true。</li>
     * </ul>
     * </p>
     */
    @GetMapping("/clients")
    public Result<List<Map<String, Object>>> clients() {
        List<OAuth2RegisteredClient> all = clientMapper.selectAllExcluding("portal-app");
        List<Map<String, Object>> result = new ArrayList<>();

        for (OAuth2RegisteredClient client : all) {
            String clientId = client.getClientId();
            String grants = client.getAuthorizationGrantTypes() == null ? "" : client.getAuthorizationGrantTypes();

            // 设备码客户端排除 (门户无法代为跳转)
            if (grants.contains("device_code")) {
                continue;
            }
            // 仅展示支持授权码模式的客户端 (点击卡片可跳转)
            if (!grants.contains("authorization_code")) {
                continue;
            }

            String redirectUris = client.getRedirectUris() == null ? "" : client.getRedirectUris();
            String redirectUri = pickRedirectUri(redirectUris);
            String homeUrl = extractHomeUrl(redirectUri);

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("clientId", clientId);
            item.put("name", client.getClientName() != null ? client.getClientName() : clientId);
            item.put("type", "web");
            item.put("redirectUri", redirectUri);
            item.put("homepage", homeUrl != null ? homeUrl : "#");
            if (isRequireProofKey(client.getClientSettings())) {
                item.put("pkce", true);
            }
            result.add(item);
        }
        return Result.ok(result);
    }

    /**
     * 从逗号分隔的 redirect_uris 中挑选一个: 优先包含 localhost, 否则取第一个.
     */
    private String pickRedirectUri(String redirectUris) {
        if (redirectUris == null || redirectUris.isBlank()) {
            return "";
        }
        String[] uris = redirectUris.split(",");
        for (String uri : uris) {
            if (uri.contains("localhost")) {
                return uri.trim();
            }
        }
        return uris[0].trim();
    }

    /**
     * 从 redirect_uri 提取客户端首页 URL.
     * <p>
     * 例: "http://localhost:8083/callback" → "http://localhost:8083/"
     * 仅处理 http/https 协议, 忽略自定义 scheme (如 com.example.mobileapp://).
     * </p>
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

    /**
     * 解析 client_settings JSON 判断是否要求 PKCE.
     * <p>
     * 该 JSON 在 oauth2_registered_client 表中存储的是 camelCase (key: requireProofKey),
     * 另有 "settings.require_proof_key" (dot 命名) 的兼容写法, 这里两者都判断。
     * </p>
     */
    private boolean isRequireProofKey(String clientSettings) {
        if (clientSettings == null || clientSettings.isBlank()) {
            return false;
        }
        try {
            JsonNode node = objectMapper.readTree(clientSettings);
            for (String key : List.of("requireProofKey", "settings.require_proof_key")) {
                JsonNode value = node.get(key);
                if (value != null && value.asBoolean(false)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }
}