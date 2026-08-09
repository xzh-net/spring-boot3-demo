package net.xzh.authserver.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.OAuth2RegisteredClient;
import net.xzh.authserver.mapper.OAuth2RegisteredClientMapper;
import net.xzh.authserver.security.repository.JdbcRegisteredClientRepository;
import net.xzh.authserver.vo.ClientVO;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientService {

    private final OAuth2RegisteredClientMapper mapper;
    private final JdbcRegisteredClientRepository repository;
    private final PasswordEncoder passwordEncoder;

    /** 列出全部客户端 (不走 AuthorizationServer 的 findAll — RegisteredClientRepository 没这个方法) */
    public List<OAuth2RegisteredClient> list() {
        return mapper.selectList(null);
    }

    public ClientVO get(String id) {
        OAuth2RegisteredClient entity = mapper.selectById(id);
        if (entity == null) return null;
        return entityToVO(entity);
    }

    @Transactional
    public String create(ClientVO vo) {
        String id = UUID.randomUUID().toString().replace("-", "");
        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(vo.getClientId())
                .clientIdIssuedAt(Instant.now())
                .clientName(vo.getClientName())
                .clientAuthenticationMethods(m -> {
                    if (vo.getClientAuthenticationMethods() != null) {
                        vo.getClientAuthenticationMethods().forEach(v -> m.add(new ClientAuthenticationMethod(v)));
                    }
                })
                .authorizationGrantTypes(t -> {
                    if (vo.getAuthorizationGrantTypes() != null) {
                        vo.getAuthorizationGrantTypes().forEach(v -> t.add(mapGrantType(v)));
                    }
                })
                .scopes(s -> {
                    if (vo.getScopes() != null) vo.getScopes().forEach(s::add);
                });

        if (StringUtils.hasText(vo.getClientSecret())) {
            builder.clientSecret("{bcrypt}" + passwordEncoder.encode(vo.getClientSecret()));
        }
        if (vo.getRedirectUris() != null) {
            builder.redirectUris(u -> vo.getRedirectUris().forEach(u::add));
        }
        if (vo.getPostLogoutRedirectUris() != null) {
            builder.postLogoutRedirectUris(u -> vo.getPostLogoutRedirectUris().forEach(u::add));
        }

        Map<String, Object> clientSettings = new HashMap<>();
        clientSettings.put("requireProofKey", vo.isRequireProofKey());
        clientSettings.put("requireAuthorizationConsent", vo.isRequireAuthorizationConsent());
        builder.clientSettings(ClientSettings.withSettings(clientSettings).build());

        TokenSettings.Builder ts = TokenSettings.builder();
        // 全局固定 opaque token, 不接受前端传入的 accessTokenFormat
        ts.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
        if (StringUtils.hasText(vo.getAccessTokenTimeToLive())) {
            ts.accessTokenTimeToLive(Duration.parse(vo.getAccessTokenTimeToLive()));
        }
        if (StringUtils.hasText(vo.getAuthorizationCodeTimeToLive())) {
            ts.authorizationCodeTimeToLive(Duration.parse(vo.getAuthorizationCodeTimeToLive()));
        }
        ts.reuseRefreshTokens(vo.isReuseRefreshTokens());
        builder.tokenSettings(ts.build());

        repository.save(builder.build());
        log.info("新增客户端 clientId={}", vo.getClientId());
        return id;
    }

    @Transactional
    public void update(String id, ClientVO vo) {
        RegisteredClient existing = repository.findById(id);
        if (existing == null) throw new IllegalArgumentException("客户端不存在: " + id);

        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(existing.getClientId())
                .clientIdIssuedAt(existing.getClientIdIssuedAt())
                .clientName(StringUtils.hasText(vo.getClientName()) ? vo.getClientName() : existing.getClientName())
                .clientAuthenticationMethods(m -> {
                    if (vo.getClientAuthenticationMethods() != null) {
                        vo.getClientAuthenticationMethods().forEach(v -> m.add(new ClientAuthenticationMethod(v)));
                    } else {
                        existing.getClientAuthenticationMethods().forEach(m::add);
                    }
                })
                .authorizationGrantTypes(t -> {
                    if (vo.getAuthorizationGrantTypes() != null) {
                        vo.getAuthorizationGrantTypes().forEach(v -> t.add(mapGrantType(v)));
                    } else {
                        existing.getAuthorizationGrantTypes().forEach(t::add);
                    }
                })
                .scopes(s -> {
                    if (vo.getScopes() != null) {
                        vo.getScopes().forEach(s::add);
                    } else {
                        existing.getScopes().forEach(s::add);
                    }
                });

        // Secret: 只有传了新密码才覆盖
        if (StringUtils.hasText(vo.getClientSecret())) {
            builder.clientSecret("{bcrypt}" + passwordEncoder.encode(vo.getClientSecret()));
        } else if (existing.getClientSecret() != null) {
            builder.clientSecret(existing.getClientSecret());
        }

        if (vo.getRedirectUris() != null) {
            builder.redirectUris(u -> vo.getRedirectUris().forEach(u::add));
        } else {
            builder.redirectUris(u -> existing.getRedirectUris().forEach(u::add));
        }
        if (vo.getPostLogoutRedirectUris() != null) {
            builder.postLogoutRedirectUris(u -> vo.getPostLogoutRedirectUris().forEach(u::add));
        } else {
            builder.postLogoutRedirectUris(u -> existing.getPostLogoutRedirectUris().forEach(u::add));
        }

        Map<String, Object> clientSettings = new HashMap<>();
        clientSettings.put("requireProofKey", vo.isRequireProofKey());
        clientSettings.put("requireAuthorizationConsent", vo.isRequireAuthorizationConsent());
        builder.clientSettings(ClientSettings.withSettings(clientSettings).build());

        TokenSettings.Builder ts = TokenSettings.builder();
        // 全局固定 opaque token, 不接受前端传入的 accessTokenFormat
        ts.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
        if (StringUtils.hasText(vo.getAccessTokenTimeToLive())) {
            ts.accessTokenTimeToLive(Duration.parse(vo.getAccessTokenTimeToLive()));
        }
        if (StringUtils.hasText(vo.getAuthorizationCodeTimeToLive())) {
            ts.authorizationCodeTimeToLive(Duration.parse(vo.getAuthorizationCodeTimeToLive()));
        }
        ts.reuseRefreshTokens(vo.isReuseRefreshTokens());
        builder.tokenSettings(ts.build());

        repository.save(builder.build()); // save 内部已触发 Redis 缓存刷新
        log.info("更新客户端 id={}", id);
    }

    @Transactional
    public void delete(String id) {
        repository.delete(id); // 内部已清 Redis 缓存
        log.info("删除客户端 id={}", id);
    }

    public String resetSecret(String id) {
        RegisteredClient existing = repository.findById(id);
        if (existing == null) throw new IllegalArgumentException("客户端不存在: " + id);
        String newSecret = UUID.randomUUID().toString().replace("-", "").substring(0, 16);

        RegisteredClient.Builder builder = RegisteredClient.withId(id)
                .clientId(existing.getClientId())
                .clientIdIssuedAt(existing.getClientIdIssuedAt())
                .clientSecret("{bcrypt}" + passwordEncoder.encode(newSecret))
                .clientSecretExpiresAt(existing.getClientSecretExpiresAt())
                .clientName(existing.getClientName())
                .clientAuthenticationMethods(m -> existing.getClientAuthenticationMethods().forEach(m::add))
                .authorizationGrantTypes(t -> existing.getAuthorizationGrantTypes().forEach(t::add))
                .redirectUris(u -> existing.getRedirectUris().forEach(u::add))
                .postLogoutRedirectUris(u -> existing.getPostLogoutRedirectUris().forEach(u::add))
                .scopes(s -> existing.getScopes().forEach(s::add))
                .clientSettings(existing.getClientSettings())
                .tokenSettings(existing.getTokenSettings());
        repository.save(builder.build());
        log.info("重置客户端密钥 id={}", id);
        return newSecret;
    }

    // ------------------------------------------------------------------

    private AuthorizationGrantType mapGrantType(String v) {
        return switch (v) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "password" -> new AuthorizationGrantType("password");
            case "urn:ietf:params:oauth:grant-type:device_code" -> AuthorizationGrantType.DEVICE_CODE;
            default -> new AuthorizationGrantType(v);
        };
    }

    private ClientVO entityToVO(OAuth2RegisteredClient entity) {
        ClientVO vo = new ClientVO();
        vo.setId(entity.getId());
        vo.setClientId(entity.getClientId());
        vo.setClientName(entity.getClientName());
        vo.setClientSecret(entity.getClientSecret());

        if (StringUtils.hasText(entity.getClientAuthenticationMethods())) {
            vo.setClientAuthenticationMethods(Set.of(entity.getClientAuthenticationMethods().split(",")));
        }
        if (StringUtils.hasText(entity.getAuthorizationGrantTypes())) {
            vo.setAuthorizationGrantTypes(Set.of(entity.getAuthorizationGrantTypes().split(",")));
        }
        if (StringUtils.hasText(entity.getRedirectUris())) {
            vo.setRedirectUris(Set.of(entity.getRedirectUris().split(",")));
        }
        if (StringUtils.hasText(entity.getPostLogoutRedirectUris())) {
            vo.setPostLogoutRedirectUris(Set.of(entity.getPostLogoutRedirectUris().split(",")));
        }
        if (StringUtils.hasText(entity.getScopes())) {
            vo.setScopes(Set.of(entity.getScopes().split(",")));
        }
        if (StringUtils.hasText(entity.getClientSettings())) {
            try {
                Map<String, Object> cs = new ObjectMapper()
                        .readValue(entity.getClientSettings(), new TypeReference<>() {});
                vo.setRequireProofKey((Boolean) cs.getOrDefault("requireProofKey", false));
                vo.setRequireAuthorizationConsent((Boolean) cs.getOrDefault("requireAuthorizationConsent", false));
            } catch (Exception ignored) {}
        }
        if (StringUtils.hasText(entity.getTokenSettings())) {
            try {
                Map<String, Object> ts = new ObjectMapper()
                        .readValue(entity.getTokenSettings(), new TypeReference<>() {});
                vo.setAccessTokenFormat((String) ts.getOrDefault("accessTokenFormat", "REFERENCE"));
                vo.setAccessTokenTimeToLive((String) ts.getOrDefault("accessTokenTimeToLive", "PT2H"));
                vo.setAuthorizationCodeTimeToLive((String) ts.getOrDefault("authorizationCodeTimeToLive", "PT5M"));
                vo.setReuseRefreshTokens((Boolean) ts.getOrDefault("reuseRefreshTokens", true));
            } catch (Exception ignored) {}
        }
        return vo;
    }
}
