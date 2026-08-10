package net.xzh.authserver.security.repository;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.OAuth2AuthorizationConsentEntity;
import net.xzh.authserver.entity.OAuth2AuthorizationRecordEntity;
import net.xzh.authserver.mapper.OAuth2AuthorizationConsentMapper;
import net.xzh.authserver.mapper.OAuth2AuthorizationRecordMapper;

/**
 * JDBC 持久化的 OAuth2AuthorizationConsentService 实现.
 * <p>
 * 职责：
 * 1. 将用户的 OAuth2 授权同意（consent）持久化到 MySQL oauth2_authorization_consent 表。
 * 2. 记录每次授权操作到 oauth2_authorization_record 表（审计日志）。
 * 3. 支持按 (clientId, principalName) 查询和删除授权同意。
 *
 * 架构定位：
 * 属于 repository 层，实现 SAS 的 OAuth2AuthorizationConsentService 接口。
 * 与 RedisOAuth2AuthorizationService（token 数据存 Redis）不同，
 * consent 数据存 MySQL 以支持持久化审计和管理后台查询。
 */
@Slf4j
@Repository
@RequiredArgsConstructor
public final class JdbcOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    /** 授权同意数据访问接口 */
    private final OAuth2AuthorizationConsentMapper mapper;
    /** 授权记录审计日志数据访问接口 */
    private final OAuth2AuthorizationRecordMapper recordMapper;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = new OAuth2AuthorizationConsentEntity();
        entity.setRegisteredClientId(authorizationConsent.getRegisteredClientId());
        entity.setPrincipalName(authorizationConsent.getPrincipalName());
        entity.setAuthorities(authorizationConsent.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")));

        OAuth2AuthorizationConsentEntity existing = mapper.selectById(
                entity.getRegisteredClientId(), entity.getPrincipalName());
        if (existing != null) {
            // 更新只改 authorities; firstGrantTime 保留原值 (只在首次 insert 时写一次)
            mapper.updateById(entity);
        } else {
            entity.setFirstGrantTime(LocalDateTime.now());
            mapper.insert(entity);
        }

        // 写入授权记录 (谁、何时、向哪个客户端、通过哪种 grant_type、授予了什么权限)
        saveAuthorizationRecord(entity);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        mapper.deleteById(authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName());

        // 标记授权记录为已撤销
        try {
            recordMapper.revokeActiveConsent(
                    authorizationConsent.getRegisteredClientId(),
                    authorizationConsent.getPrincipalName());
        } catch (Exception e) {
            log.warn("标记授权记录为已撤销失败: {}", e.getMessage());
        }
    }

    /**
     * 保存授权记录到 oauth2_authorization_record 表。
     * 每次用户授权 (新增或更新) 都写入一条日志, 同时记录本次授权是通过哪种 grant_type 进来的。
     * grant_type 来源: Spring 框架调用 consentService.save() 时必处于一次 HTTP 请求线程,
     * 从 RequestContextHolder 中拿当前 request 的 URI 判断:
     * - /oauth2/authorize → authorization_code
     * - /oauth2/device/verify → urn:ietf:params:oauth:grant-type:device_code
     * 取不到时写 null, 不影响主流程。
     */
    private void saveAuthorizationRecord(OAuth2AuthorizationConsentEntity entity) {
        try {
            OAuth2AuthorizationRecordEntity record = new OAuth2AuthorizationRecordEntity();
            record.setRegisteredClientId(entity.getRegisteredClientId());
            record.setPrincipalName(entity.getPrincipalName());
            record.setGrantedAuthorities(entity.getAuthorities());
            record.setGrantTime(LocalDateTime.now());
            record.setStatus("active");
            record.setGrantType(resolveGrantTypeFromRequest());
            recordMapper.insert(record);
        } catch (Exception e) {
            log.warn("保存授权记录失败 (不影响授权流程): {}", e.getMessage());
        }
    }

    /**
     * 从当前请求 URI 判断本次 consent 提交属于哪种 grant_type 流程。
     * 取不到或判断不出返回 null。
     */
    private String resolveGrantTypeFromRequest() {
        try {
            var attrs = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            HttpServletRequest request = attrs.getRequest();
            if (request == null) return null;
            String uri = request.getRequestURI();
            if (uri == null) return null;
            if (uri.contains("/oauth2/device/verify")) {
                return "urn:ietf:params:oauth:grant-type:device_code";
            }
            if (uri.contains("/oauth2/authorize")) {
                return "authorization_code";
            }
            return null;
        } catch (Exception e) {
            log.debug("无法从 RequestContextHolder 解析 grant_type: {}", e.getMessage());
            return null;
        }
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        OAuth2AuthorizationConsentEntity entity = mapper.selectById(registeredClientId, principalName);
        if (entity == null) return null;
        return buildConsent(entity);
    }

    // ------------------------------------------------------------------

    private OAuth2AuthorizationConsent buildConsent(OAuth2AuthorizationConsentEntity entity) {
        return parseConsent(entity.getRegisteredClientId(), entity.getPrincipalName(), entity.getAuthorities());
    }

    private OAuth2AuthorizationConsent parseConsent(String registeredClientId, String principalName, String authoritiesStr) {
        Set<GrantedAuthority> authorities = Stream.of(
                        StringUtils.hasText(authoritiesStr) ? authoritiesStr.split(",") : new String[0])
                .map(s -> new SimpleGrantedAuthority(s.trim()))
                .collect(Collectors.toCollection(HashSet::new));

        return OAuth2AuthorizationConsent.withId(registeredClientId, principalName)
                .authorities(a -> a.addAll(authorities))
                .build();
    }
}
