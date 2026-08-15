package net.xzh.authserver.controller.api;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.entity.OAuth2AuthorizationConsentEntity;
import net.xzh.authserver.entity.OAuth2AuthorizationRecordEntity;
import net.xzh.authserver.mapper.OAuth2AuthorizationConsentMapper;
import net.xzh.authserver.mapper.OAuth2AuthorizationRecordMapper;
import net.xzh.authserver.service.AuthSessionService;

/**
 * 三域管理 API — 授权记录域 (/api/admin/records).
 * <p>
 * 授权确认主表 (oauth2_authorization_consent) + 授权历史子表
 * (oauth2_authorization_record) 的 REST 接口, 经 Order(2) 安全链保护
 * (Bearer + ROLE_ADMIN)。逻辑与既有 /admin/authorization/api 对齐。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/records")
@RequiredArgsConstructor
public class AdminRecordApiController {

    private final OAuth2AuthorizationConsentMapper consentMapper;
    private final OAuth2AuthorizationRecordMapper recordMapper;
    private final OAuth2AuthorizationConsentService consentService;
    private final AuthSessionService authSessionService;
    private final RegisteredClientRepository clientRepository;

    @GetMapping("/consents")
    public Result<List<OAuth2AuthorizationConsentEntity>> consentList() {
        List<OAuth2AuthorizationConsentEntity> list = consentMapper.listAll();
        for (OAuth2AuthorizationConsentEntity c : list) {
            c.setClientName(resolveClientName(c.getRegisteredClientId()));
            c.setGrantTypes(resolveGrantTypes(c.getRegisteredClientId(), c.getPrincipalName()));
        }
        return Result.ok(list);
    }

    @GetMapping
    public Result<List<OAuth2AuthorizationRecordEntity>> list(
            @RequestParam(required = false) String clientId,
            @RequestParam(required = false) String principalName) {
        QueryWrapper<OAuth2AuthorizationRecordEntity> qw = new QueryWrapper<>();
        if (clientId != null && !clientId.isEmpty()) {
            qw.eq("registered_client_id", clientId);
        }
        if (principalName != null && !principalName.isEmpty()) {
            qw.eq("principal_name", principalName);
        }
        qw.orderByDesc("grant_time");
        List<OAuth2AuthorizationRecordEntity> records = recordMapper.selectList(qw);
        for (OAuth2AuthorizationRecordEntity r : records) {
            if (r.getClientName() == null || r.getClientName().isEmpty()) {
                r.setClientName(resolveClientName(r.getRegisteredClientId()));
            }
        }
        return Result.ok(records);
    }

    @DeleteMapping
    public Result<Void> revoke(@RequestParam String clientId, @RequestParam String principalName) {
        try {
            log.info("取消授权开始 client={}, user={}", clientId, principalName);
            OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(clientId, principalName)
                    .authority(new SimpleGrantedAuthority("SCOPE_DUMMY"))
                    .build();
            consentService.remove(consent);
            try {
                int kicked = authSessionService.revokeByPrincipalAndClient(principalName, clientId);
                log.info("取消授权强制下线 client={}, user={}, 会话数={}", clientId, principalName, kicked);
            } catch (Exception e) {
                log.warn("取消授权强制下线失败 client={}, user={}, error={}", clientId, principalName, e.getMessage());
            }
            recordMapper.revokeActiveConsent(clientId, principalName);
            return Result.ok();
        } catch (Exception e) {
            log.error("取消授权异常", e);
            return Result.fail("取消授权失败: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }
    }

    private String resolveClientName(String clientId) {
        try {
            RegisteredClient client = clientRepository.findByClientId(clientId);
            return client != null ? client.getClientName() : clientId;
        } catch (Exception e) {
            return clientId;
        }
    }

    private List<String> resolveGrantTypes(String clientId, String principalName) {
        QueryWrapper<OAuth2AuthorizationRecordEntity> qw = new QueryWrapper<>();
        qw.eq("registered_client_id", clientId)
                .eq("principal_name", principalName)
                .isNotNull("grant_type")
                .ne("grant_type", "")
                .select("DISTINCT grant_type");
        return recordMapper.selectList(qw).stream()
                .map(OAuth2AuthorizationRecordEntity::getGrantType)
                .filter(gt -> gt != null && !gt.isBlank())
                .distinct()
                .collect(Collectors.toList());
    }
}
