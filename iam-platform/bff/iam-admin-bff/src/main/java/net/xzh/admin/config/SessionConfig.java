package net.xzh.admin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Spring Session 存储配置 (生产化三件套之一: 会话/token 持久化到 Redis).
 * <p>
 * 两个 Bean 各解决一个坑, 都不能省:
 * <ol>
 *   <li><b>DefaultCookieSerializer — Cookie 改名</b>: Spring Session 默认 Cookie 名为
 *       {@code SESSION} (DefaultCookieSerializer 构造器默认值), 而认证中心 9000 同样使用
 *       Spring Session — 两者同在 localhost 域, Cookie 不分端口, 默认名会互相覆盖,
 *       导致 8085 → 9000 → 8085 跳转中 HttpSession 丢失 (state mismatch, 登录必失败)。
 *       这是 portal-bff 用 {@code server.servlet.session.cookie.name} 改名解决的同一问题 —
 *       但该属性只对 servlet 容器原生会话生效, Spring Session 接管后不认它,
 *       必须用本类的 CookieSerializer Bean (官方手法)。
 *       三端 Cookie 命名: 9000=SESSION / portal-bff=PORTAL_SERVER_SESSION / admin-bff=ADMIN_SERVER_SESSION。</li>
 *   <li><b>HttpSessionOAuth2AuthorizedClientRepository — token 随 session 走</b>:
 *       Spring Boot 默认提供 AuthenticatedPrincipalOAuth2AuthorizedClientRepository
 *       (@ConditionalOnMissingBean), 把 access/refresh token 存进程内 Map (按 principal 索引) —
 *       重启即丢、多实例不共享, 出现"session 活着但 token 没了"的僵尸态。
 *       换成本实现后 token 作为 session 属性随 HttpSession 一起序列化进 Redis:
 *       重启不丢、多实例共享、登出 invalidate 连带清除 (AuthLogoutController 另有显式清理双保险)。
 *       序列化前提已静态验证: OAuth2AuthorizedClient/ClientRegistration/token/ProviderDetails
 *       全链 Serializable (2026-11-02 javap 闭包检查 5/5)。</li>
 * </ol>
 * Redis 键前缀由 application.yml 的 {@code spring.session.redis.namespace=admin-bff:session}
 * 标识, 且存储于独立的 db3 (db1=认证中心 9000 专用) —— 物理分库 + namespace 双层隔离,
 * 两应用互不可见, 避免键混放误解与 FLUSHDB 连坐。
 */
@Configuration
public class SessionConfig {

    /**
     * Session Cookie 改名: ADMIN_SERVER_SESSION (与 9000 的 SESSION 隔离).
     * <p>
     * 仅改名, 其余属性 (HttpOnly/Path/SameSite) 用默认值, 与 9000 行为一致。
     */
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("ADMIN_SERVER_SESSION");
        return serializer;
    }

    /**
     * 授权客户端存储改为 HttpSession 版 (默认 Bean 为 @ConditionalOnMissingBean, 本 Bean 存在即顶替).
     * <p>
     * 影响面: oauth2Login 回调存 token、{@code @RegisteredOAuth2AuthorizedClient} 取 token
     * (ApiProxyController 透传 Bearer 用)、TokenValidationFilter 校验取 token —— 三者
     * 统一走 session, session 在 Redis, 于是 token 也持久化且三处一致。
     */
    @Bean
    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }
}
