package net.xzh.authserver.controller.admin;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

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
 * 模块授权查询管理 — 主子表模式:
 * 主表 oauth2_authorization_consent  : 展示当前已授权的用户 (按 client+user 维度)
 * 子表 oauth2_authorization_record  : 每次授权的历史明细
 */
@Slf4j
@Controller
@RequestMapping("/admin/authorization")
@RequiredArgsConstructor
public class AuthorizationRecordController {

    private final OAuth2AuthorizationConsentMapper consentMapper;
    private final OAuth2AuthorizationRecordMapper recordMapper;
    private final OAuth2AuthorizationConsentService consentService;
    private final AuthSessionService authSessionService;
    private final RegisteredClientRepository clientRepository;

    @GetMapping()
    public String page() {
        return "admin/authorization";
    }

    // ------------------------------------------------------------------
    // 主表: 已授权用户列表 (oauth2_authorization_consent)
    // ------------------------------------------------------------------

    /**
     * 查询所有已授权的用户 (主表数据)。
     */
    @GetMapping("/api/consent-list")
    @ResponseBody
    public Result<List<OAuth2AuthorizationConsentEntity>> consentList() {
        List<OAuth2AuthorizationConsentEntity> list = consentMapper.listAll();
        for (OAuth2AuthorizationConsentEntity c : list) {
            c.setClientName(resolveClientName(c.getRegisteredClientId()));
            // 从 record 表聚合该 (client, user) 的所有授权类型 (去重)
            c.setGrantTypes(resolveGrantTypes(c.getRegisteredClientId(), c.getPrincipalName()));
        }
        return Result.ok(list);
    }

    // ------------------------------------------------------------------
    // 子表: 授权历史明细 (oauth2_authorization_record)
    // ------------------------------------------------------------------

    /**
     * 查询授权历史明细, 支持按 clientId + principalName 过滤。
     */
    @GetMapping("/api/list")
    @ResponseBody
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

    // ------------------------------------------------------------------
    // 取消授权: 删 consent + 强制下线 + 标记 record 撤销
    // ------------------------------------------------------------------

    /**
     * 取消授权: 删除 consent + 强制下线该用户在该客户端上的所有会话 + 标记记录为已撤销。
     */
    @DeleteMapping("/api/revoke")
    @ResponseBody
    public Result<Void> revoke(@RequestParam String clientId, @RequestParam String principalName) {
        try {
            log.info("取消授权开始 client={}, user={}", clientId, principalName);

            // 1. 删除 OAuth2 授权确认 (DB)
            // Spring Authorization Server 1.4.x 要求 OAuth2AuthorizationConsent 至少有一个 authority
            OAuth2AuthorizationConsent consent = OAuth2AuthorizationConsent.withId(clientId, principalName)
                    .authority(new SimpleGrantedAuthority("SCOPE_DUMMY"))
                    .build();
            consentService.remove(consent);
            log.info("取消授权 consent 已删除 client={}, user={}", clientId, principalName);

            // 2. 强制下线该用户在该客户端上的所有会话 (JWT 加入黑名单)
            try {
                int kicked = authSessionService.revokeByPrincipalAndClient(principalName, clientId);
                log.info("取消授权强制下线 client={}, user={}, 会话数={}", clientId, principalName, kicked);
            } catch (Exception e) {
                log.warn("取消授权强制下线失败 client={}, user={}, error={}", clientId, principalName, e.getMessage());
            }

            // 3. 标记记录为已撤销
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

    /**
     * 从 record 表查出该 (client, user) 的所有授权类型 (去重, 过滤 null).
     */
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
