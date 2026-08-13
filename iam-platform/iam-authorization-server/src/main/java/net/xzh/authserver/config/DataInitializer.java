package net.xzh.authserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.security.repository.JdbcRegisteredClientRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 数据初始化器.
 * <p>
 * 应用启动时检查并更新 portal-app 客户端配置，
 * 确保 redirect_uri 指向独立的 iam-portal-service (8080) 而非认证中心本机。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final JdbcRegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * portal-app 客户端密钥.
     * <p>
     * iam-portal-service (8080) 的 application.yml 中 client-secret 必须与此值一致。
     */
    private static final String PORTAL_CLIENT_SECRET = "123456";

    /**
     * iam-portal-service 的 OAuth2 回调地址.
     * <p>
     * Spring Security OAuth2 Client 默认回调路径: {baseUrl}/login/oauth2/code/{registrationId}
     * registrationId = portal-app-oidc (见 iam-portal-service application.yml)
     * <p>
     * 设计文档 §6-7: 额外加入 web-app (8081) 和 mobile-app (8083) 的 /portal-sso-callback 地址,
     * 因为「应用 A → 门户」时, 会为 portal-app 客户端发起 prompt=none 静默授权,
     * 授权响应需要回调到各应用自己的 /portal-sso-callback 端点做中转.
     */
    private static final String PORTAL_REDIRECT_URI = "http://localhost:8080/login/oauth2/code/portal-app-oidc";
    private static final String WEB_APP_PORTAL_SSO_URI = "http://localhost:8081/portal-sso-callback";
    private static final String MOBILE_APP_PORTAL_SSO_URI = "http://localhost:8083/portal-sso-callback";
    private static final String PORTAL_POST_LOGOUT_REDIRECT_URI = "http://localhost:8000/logged-out";

    @Override
    public void run(ApplicationArguments args) {
        ensurePortalAppClient();
        ensureResourceServerClient();
    }

    /**
     * 确保门户应用客户端配置正确.
     * <p>
     * 如果 portal-app 不存在则创建; 已存在则校验 redirect_uri / 密钥是否需要更新。
     * 密钥使用 BCrypt 哈希存储, 校验时用 matches() 比对。
     */
    private void ensurePortalAppClient() {
        try {
            RegisteredClient existing = clientRepository.findByClientId("portal-app");
            if (existing == null) {
                createPortalAppClient();
                return;
            }

            // 已存在: 校验 redirect_uri / 密钥 / PKCE 配置是否需要更新
            boolean needsUpdate = false;
            RegisteredClient.Builder builder = RegisteredClient.from(existing);

            // 设计文档 §6-7: 校验 redirect_uri 必须包含 3 个 URI
            Set<String> expectedRedirects = Set.of(
                    PORTAL_REDIRECT_URI,
                    WEB_APP_PORTAL_SSO_URI,
                    MOBILE_APP_PORTAL_SSO_URI
            );
            Set<String> actualRedirects = existing.getRedirectUris().stream()
                    .map(Object::toString)
                    .collect(Collectors.toSet());
            if (!actualRedirects.containsAll(expectedRedirects)) {
                log.info("[DataInit] portal-app redirect_uri 需更新为 3 个 (iam-portal-service/web-app/mobile-app)");
                // 用 builder 逐个添加 (保留已有 URI, 补上缺失的)
                expectedRedirects.forEach(builder::redirectUri);
                needsUpdate = true;
            }

            // 校验 postLogoutRedirectUri
            boolean hasCorrectPostLogout = existing.getPostLogoutRedirectUris().stream()
                    .anyMatch(uri -> PORTAL_POST_LOGOUT_REDIRECT_URI.equals(uri.toString()));
            if (!hasCorrectPostLogout) {
                log.info("[DataInit] portal-app postLogoutRedirectUri 需更新");
                builder.postLogoutRedirectUri(PORTAL_POST_LOGOUT_REDIRECT_URI);
                needsUpdate = true;
            }

            // 设计文档 §4: Portal 客户端强制启用 PKCE (即使 Confidential Client)
            if (!existing.getClientSettings().isRequireProofKey()) {
                log.info("[DataInit] portal-app requireProofKey 需更新为 true (PKCE)");
                builder.clientSettings(ClientSettings.withSettings(existing.getClientSettings().getSettings())
                        .requireProofKey(true)
                        .build());
                needsUpdate = true;
            }

            // 校验密钥是否匹配
            if (existing.getClientSecret() == null
                    || !passwordEncoder.matches(PORTAL_CLIENT_SECRET, existing.getClientSecret())) {
                log.info("[DataInit] portal-app 密钥需更新");
                builder.clientSecret(passwordEncoder.encode(PORTAL_CLIENT_SECRET));
                needsUpdate = true;
            }

            if (needsUpdate) {
                clientRepository.save(builder.build());
                log.info("[DataInit] portal-app 客户端配置已更新 (redirect_uri={}, secret={})",
                        PORTAL_REDIRECT_URI, PORTAL_CLIENT_SECRET);
            } else {
                log.info("[DataInit] portal-app 客户端配置正确, 跳过");
            }
        } catch (Exception e) {
            log.error("[DataInit] 处理 portal-app 客户端失败", e);
        }
    }

    /**
     * 创建 portal-app 客户端 (首次启动).
     */
    private void createPortalAppClient() {
        try {
            String secretHash = passwordEncoder.encode(PORTAL_CLIENT_SECRET);

            RegisteredClient portalApp = RegisteredClient.withId("1")
                    .clientId("portal-app")
                    .clientSecret(secretHash)
                    .clientName("门户应用 (SSO)")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    // 设计文档 §6-7: portal-app 需要接收 3 处回调
                    .redirectUri(PORTAL_REDIRECT_URI)           // iam-portal-service 自己的 OAuth2 login 回调
                    .redirectUri(WEB_APP_PORTAL_SSO_URI)        // web-app → 门户 SSO prompt=none 中转
                    .redirectUri(MOBILE_APP_PORTAL_SSO_URI)     // mobile-app → 门户 SSO prompt=none 中转
                    .postLogoutRedirectUri(PORTAL_POST_LOGOUT_REDIRECT_URI)
                    .scope("openid")
                    .scope("profile")
                    .scope("email")
                    .clientSettings(ClientSettings.builder()
                            // 设计文档 §4: Portal 虽然是 Confidential Client, 仍强制启用 PKCE
                            .requireProofKey(true)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenFormat(org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.REFERENCE)
                            .accessTokenTimeToLive(Duration.ofHours(2))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            clientRepository.save(portalApp);
            log.info("[DataInit] portal-app 客户端创建成功 (redirect_uri={}, secret={})",
                    PORTAL_REDIRECT_URI, PORTAL_CLIENT_SECRET);
        } catch (Exception e) {
            log.error("[DataInit] 创建 portal-app 客户端失败", e);
        }
    }

    /**
     * 获取 portal-app 客户端的密钥.
     */
    public static String getPortalClientSecret() {
        return PORTAL_CLIENT_SECRET;
    }

    /**
     * 确保 resource-server 客户端存在 (专属 introspection 调用的集群身份).
     * <p>
     * 数据库如果是从旧版 schema.sql 初始化的 (resource-server 客户端尚未加入),
     * 则 resource-server 缺失会导致 iam-resource-service 调用
     * /oauth2/introspect 时因客户端认证失败返回 401。这里兜底补建。
     * </p>
     */
    private void ensureResourceServerClient() {
        try {
            RegisteredClient existing = clientRepository.findByClientId("resource-server");
            if (existing != null) {
                return;
            }
            String secretHash = passwordEncoder.encode("123456");
            RegisteredClient client = RegisteredClient.withId("6")
                    .clientId("resource-server")
                    .clientSecret(secretHash)
                    .clientName("资源服务器")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope("read")
                    .scope("write")
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(false)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenFormat(org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.REFERENCE)
                            .accessTokenTimeToLive(Duration.ofMinutes(30))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();
            clientRepository.save(client);
            log.info("[DataInit] resource-server 客户端已创建 (introspection 专用)");
        } catch (Exception e) {
            log.error("[DataInit] 创建 resource-server 客户端失败", e);
        }
    }
}
