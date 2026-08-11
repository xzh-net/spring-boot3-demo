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

/**
 * 数据初始化器.
 * <p>
 * 应用启动时检查并添加必要的OAuth2客户端配置，
 * 确保系统完整功能可用。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationRunner {

    private final JdbcRegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    private static final String PORTAL_CLIENT_SECRET = "portal-app-secret";

    @Override
    public void run(ApplicationArguments args) {
        ensurePortalAppClient();
    }

    /**
     * 确保门户应用客户端存在.
     */
    private void ensurePortalAppClient() {
        try {
            RegisteredClient existing = clientRepository.findByClientId("portal-app");
            if (existing != null && existing.getClientSecret() != null) {
                log.info("[DataInit] portal-app 客户端已存在且有密钥, 跳过初始化");
                return;
            }

            String secretHash = passwordEncoder.encode(PORTAL_CLIENT_SECRET);

            RegisteredClient portalApp = RegisteredClient.withId("5")
                    .clientId("portal-app")
                    .clientSecret(secretHash)
                    .clientName("门户应用 (SSO)")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:9000/portal.html")
                    .redirectUri("http://127.0.0.1:9000/portal.html")
                    .postLogoutRedirectUri("http://localhost:9000/login.html")
                    .scope("openid")
                    .scope("profile")
                    .scope("email")
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(false)
                            .requireAuthorizationConsent(false)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenFormat(org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat.REFERENCE)
                            .accessTokenTimeToLive(Duration.ofHours(2))
                            .reuseRefreshTokens(false)
                            .build())
                    .build();

            clientRepository.save(portalApp);
            log.info("[DataInit] portal-app 客户端初始化成功 (secret={})", PORTAL_CLIENT_SECRET);
        } catch (Exception e) {
            log.error("[DataInit] 初始化 portal-app 客户端失败", e);
        }
    }

    /**
     * 获取portal-app客户端的密钥（用于后端token交换）.
     */
    public static String getPortalClientSecret() {
        return PORTAL_CLIENT_SECRET;
    }
}
