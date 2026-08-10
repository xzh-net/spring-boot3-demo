package net.xzh.authserver.security.repository;

import net.xzh.authserver.entity.OAuth2RegisteredClient;
import net.xzh.authserver.mapper.OAuth2RegisteredClientMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * JDBC + Redis 双层缓存的 RegisteredClientRepository 实现.
 * <p>
 * 职责：
 * 1. 从 MySQL 读取客户端配置（oauth2_registered_client 表），Redis 缓存 1 小时。
 * 2. 管理客户端配置的增删改查，变更时自动刷新 Redis 缓存。
 * 3. 处理 RegisteredClient 与实体之间的序列化/反序列化转换。
 *
 * 架构定位：
 * 属于 repository 层，实现 SAS 的 RegisteredClientRepository 接口。
 * Token 格式强制 Opaque（REFERENCE），不允许客户端覆盖。
 * 客户端认证方法支持 NONE（公共客户端）和 CLIENT_SECRET_BASIC（机密客户端）。
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public final class JdbcRegisteredClientRepository implements RegisteredClientRepository {

    /** Redis key 前缀：按 ID 缓存客户端配置 */
    private static final String CACHE_BY_ID = "oauth2:client:id:";
    /** Redis key 前缀：按 clientId 缓存客户端配置 */
    private static final String CACHE_BY_CLIENT_ID = "oauth2:client:cid:";
    /** Redis 缓存过期时间（1 小时） */
    private static final Duration CACHE_TTL = Duration.ofHours(1);

    /** 客户端配置数据访问接口 */
    private final OAuth2RegisteredClientMapper mapper;
    /** Redis 操作模板，用于缓存客户端配置 */
    private final StringRedisTemplate redisTemplate;
    /** JSON 序列化/反序列化工具 */
    private final ObjectMapper objectMapper;

    @Override
    public void save(RegisteredClient registeredClient) {
        OAuth2RegisteredClient entity = toEntity(registeredClient);
        if (mapper.selectById(entity.getId()) != null) {
            mapper.updateById(entity);
        } else {
            mapper.insert(entity);
        }
        refreshCache(entity);
    }

    public void delete(String id) {
        OAuth2RegisteredClient entity = mapper.selectById(id);
        if (entity != null) {
            mapper.deleteById(id);
            evictCache(entity);
        }
    }

    @Override
    public RegisteredClient findById(String id) {
        // Cache-Aside: 先查缓存
        String json = redisTemplate.opsForValue().get(CACHE_BY_ID + id);
        if (json != null) {
            return deserializeClient(json);
        }
        OAuth2RegisteredClient entity = mapper.selectById(id);
        if (entity == null) return null;
        return cacheAndReturn(entity);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        String json = redisTemplate.opsForValue().get(CACHE_BY_CLIENT_ID + clientId);
        if (json != null) {
            return deserializeClient(json);
        }
        OAuth2RegisteredClient entity = mapper.selectByClientId(clientId);
        if (entity == null) return null;
        return cacheAndReturn(entity);
    }

    // ------------------------------------------------------------------
    // 缓存管理
    // ------------------------------------------------------------------

    private RegisteredClient cacheAndReturn(OAuth2RegisteredClient entity) {
        RegisteredClient client = toRegisteredClient(entity);
        try {
            String json = objectMapper.writeValueAsString(entity);
            redisTemplate.opsForValue().set(CACHE_BY_ID + entity.getId(), json,
                    CACHE_TTL.toMillis(), TimeUnit.MILLISECONDS);
            redisTemplate.opsForValue().set(CACHE_BY_CLIENT_ID + entity.getClientId(), json,
                    CACHE_TTL.toMillis(), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            log.warn("写入客户端缓存失败", e);
        }
        return client;
    }

    private void refreshCache(OAuth2RegisteredClient entity) {
        cacheAndReturn(entity);
    }

    private void evictCache(OAuth2RegisteredClient entity) {
        redisTemplate.delete(CACHE_BY_ID + entity.getId());
        redisTemplate.delete(CACHE_BY_CLIENT_ID + entity.getClientId());
    }

    private RegisteredClient deserializeClient(String json) {
        try {
            OAuth2RegisteredClient entity = objectMapper.readValue(json,
                    new TypeReference<OAuth2RegisteredClient>() {});
            return toRegisteredClient(entity);
        } catch (Exception e) {
            log.warn("反序列化客户端缓存失败", e);
            return null;
        }
    }

    // ------------------------------------------------------------------
    // 转换方法
    // ------------------------------------------------------------------

    private RegisteredClient toRegisteredClient(OAuth2RegisteredClient entity) {
        Set<AuthorizationGrantType> grantTypes = Arrays.stream(entity.getAuthorizationGrantTypes().split(","))
                .map(String::trim)
                .map(this::toAuthorizationGrantType)
                .collect(Collectors.toSet());

        Set<ClientAuthenticationMethod> authMethods = Arrays.stream(entity.getClientAuthenticationMethods().split(","))
                .map(String::trim)
                .map(ClientAuthenticationMethod::new)
                .collect(Collectors.toSet());

        Set<String> redirectUris = parseSet(entity.getRedirectUris());
        Set<String> postLogoutUris = parseSet(entity.getPostLogoutRedirectUris());
        Set<String> scopes = parseSet(entity.getScopes());

        ClientSettings clientSettings = parseClientSettings(entity.getClientSettings());
        TokenSettings tokenSettings = parseTokenSettings(entity.getTokenSettings());

        return RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientIdIssuedAt(toInstant(entity.getClientIdIssuedAt()))
                .clientSecret(entity.getClientSecret())
                .clientSecretExpiresAt(toInstant(entity.getClientSecretExpiresAt()))
                .clientName(entity.getClientName())
                .clientAuthenticationMethods(methods -> methods.addAll(authMethods))
                .authorizationGrantTypes(types -> types.addAll(grantTypes))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .postLogoutRedirectUris(uris -> uris.addAll(postLogoutUris))
                .scopes(s -> s.addAll(scopes))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();
    }

    private OAuth2RegisteredClient toEntity(RegisteredClient client) {
        OAuth2RegisteredClient entity = new OAuth2RegisteredClient();
        entity.setId(client.getId());
        entity.setClientId(client.getClientId());
        entity.setClientIdIssuedAt(client.getClientIdIssuedAt() != null
                ? LocalDateTime.ofInstant(client.getClientIdIssuedAt(), ZoneId.systemDefault()) : LocalDateTime.now());
        entity.setClientSecret(client.getClientSecret());
        entity.setClientSecretExpiresAt(client.getClientSecretExpiresAt() != null
                ? LocalDateTime.ofInstant(client.getClientSecretExpiresAt(), ZoneId.systemDefault()) : null);
        entity.setClientName(client.getClientName());
        entity.setClientAuthenticationMethods(client.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue).collect(Collectors.joining(",")));
        entity.setAuthorizationGrantTypes(client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue).collect(Collectors.joining(",")));
        entity.setRedirectUris(String.join(",", client.getRedirectUris()));
        entity.setPostLogoutRedirectUris(String.join(",", client.getPostLogoutRedirectUris()));
        entity.setScopes(String.join(",", client.getScopes()));

        // 统一用 camelCase key 序列化, 与 schema.sql 初始数据格式保持一致.
        //
        // 读取时不直接调用 getter (isRequireProofKey / getAccessTokenTimeToLive 等):
        //   SAS 1.4.1 这些 getter 内部会对设置值做 Boolean/Duration 自动拆箱,
        //   如果底层 setting 未设置 (null), 会触发 NPE.
        // 写入时也不直接序列化 getSettings():
        //   getSettings() 返回的 key 是 "settings.token.reuse-refresh-tokens" 这种
        //   dotted kebab-case, 与 parseTokenSettings()/entityToVO() 读取的 camelCase key
        //   不匹配, 会导致管理后台保存后再次打开时 checkbox 回到默认值.
        //
        // 所以统一通过 ClientSettings.getSetting(String)/TokenSettings.getSetting(String)
        //   按 SAS 内部实际的 dotted kebab-case key 取 Object 值, 再按类型转换.
        Map<String, Object> rawCs = client.getClientSettings().getSettings();
        Map<String, Object> csMap = new HashMap<>();
        // 注意: ClientSettings 的内部 key 是 camelCase (requireProofKey),
        // 而 TokenSettings 的内部 key 是 dotted kebab-case (settings.token.xxx).
        // 这是 SAS 1.4.1 的实际行为, 已通过 DIAG 日志验证.
        csMap.put("requireProofKey", readBoolSetting(rawCs, "requireProofKey"));
        csMap.put("requireAuthorizationConsent", readBoolSetting(rawCs, "requireAuthorizationConsent"));
        entity.setClientSettings(toJson(csMap));

        Map<String, Object> rawTs = client.getTokenSettings().getSettings();
        Map<String, Object> tsMap = new HashMap<>();
        OAuth2TokenFormat fmt = (OAuth2TokenFormat) rawTs.get("settings.token.access-token-format");
        tsMap.put("accessTokenFormat", fmt != null ? fmt.getValue() : OAuth2TokenFormat.REFERENCE.getValue());
        Duration attl = readDurationSetting(rawTs, "settings.token.access-token-time-to-live");
        tsMap.put("accessTokenTimeToLive", (attl != null ? attl : Duration.ofHours(2)).toString());
        tsMap.put("reuseRefreshTokens", readBoolSetting(rawTs, "settings.token.reuse-refresh-tokens"));
        Duration acttl = readDurationSetting(rawTs, "settings.token.authorization-code-time-to-live");
        if (acttl != null) tsMap.put("authorizationCodeTimeToLive", acttl.toString());
        entity.setTokenSettings(toJson(tsMap));
        return entity;
    }

    private Boolean readBoolSetting(Map<String, Object> map, String dottedKebabKey) {
        Object v = map.get(dottedKebabKey);
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return Boolean.parseBoolean(s);
        // SAS 的 Boolean setting 默认是 false (null 视为 false)
        return false;
    }

    private Duration readDurationSetting(Map<String, Object> map, String dottedKebabKey) {
        Object v = map.get(dottedKebabKey);
        if (v instanceof Duration d) return d;
        if (v instanceof String s) return Duration.parse(s);
        if (v instanceof Number n) return Duration.ofSeconds(n.longValue());
        return null;
    }

    private AuthorizationGrantType toAuthorizationGrantType(String value) {
        return switch (value) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "password" -> new AuthorizationGrantType("password");
            case "urn:ietf:params:oauth:grant-type:device_code" -> AuthorizationGrantType.DEVICE_CODE;
            default -> new AuthorizationGrantType(value);
        };
    }

    private Set<String> parseSet(String value) {
        if (!StringUtils.hasText(value)) return new HashSet<>();
        return new HashSet<>(Arrays.asList(value.split(",")));
    }

    private ClientSettings parseClientSettings(String json) {
        try {
            if (json == null || json.isBlank() || "{}".equals(json.trim())) {
                return ClientSettings.builder().build();
            }
            Map<String, Object> map = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
            return ClientSettings.builder()
                    .requireProofKey(Boolean.TRUE.equals(map.get("requireProofKey")))
                    .requireAuthorizationConsent(Boolean.TRUE.equals(map.get("requireAuthorizationConsent")))
                    .build();
        } catch (Exception e) {
            return ClientSettings.builder().build();
        }
    }

    private TokenSettings parseTokenSettings(String json) {
        try {
            Map<String, Object> map = json != null
                    ? objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {})
                    : new HashMap<>();
            TokenSettings.Builder builder = TokenSettings.builder();
            // access_token 格式: 项目全局固定使用 REFERENCE (Opaque 短码),
            // 不允许客户端覆盖. 无论数据库中存的是什么, 一律强制 opaque,
            // 保证 RedisOpaqueTokenIntrospector 能正确解析.
            builder.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
            if (map.containsKey("accessTokenTimeToLive")) {
                builder.accessTokenTimeToLive(Duration.parse((String) map.get("accessTokenTimeToLive")));
            }
            if (map.containsKey("reuseRefreshTokens")) {
                builder.reuseRefreshTokens((Boolean) map.get("reuseRefreshTokens"));
            }
            if (map.containsKey("authorizationCodeTimeToLive")) {
                builder.authorizationCodeTimeToLive(Duration.parse((String) map.get("authorizationCodeTimeToLive")));
            }
            return builder.build();
        } catch (Exception e) {
            // 异常时也强制 opaque, 避免回退到默认 SELF_CONTAINED (JWT)
            return TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                    .build();
        }
    }

    private String toJson(Map<String, Object> map) {
        try {
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Instant toInstant(LocalDateTime ldt) {
        return ldt != null ? ldt.atZone(ZoneId.systemDefault()).toInstant() : null;
    }
}
