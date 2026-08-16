package net.xzh.resource.controller.portal;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.mapper.SysRoleMapper;
import net.xzh.resource.service.ApplicationService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 门户客户端目录 API（资源中心 portal 端能力域，门户应用应用中心卡片所需）.
 * <p>
 * 门户（iam-portal-service）携带当前用户 Bearer Token 经此接口拉取该用户可见客户端做 SSO 卡片。
 * 准入：portal 域默认要求 {@code PORTAL_SERVICE_TOKEN}（门户服务凭证）——
 * 门户应用客户端（portal-app，属 {@code authserver.portal-client-ids} 白名单）签发的令牌
 * 由内省器注入该凭证；叠加门户客户端白名单闸门双保险，门户信息不对外任意客户端开放。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/public")
@RequiredArgsConstructor
public class PublicClientController {

    private final SysRoleMapper sysRoleMapper;

    private final ApplicationService applicationService;

    /**
     * 当前人员可见的应用/渠道客户端列表 (门户应用中心卡片).
     * <p>
     * 由 iam-portal-service 携带当前用户 Bearer Token 调用; 服务端经 Opaque Token
     * 内省取 user_code 与 RBAC 角色, 按 iam_application.visible + iam_app_authorization
     * 过滤出该用户可见的应用渠道 (含 sso_client_id / access_url), 实现"当前人员可见客户列表"。
     * </p>
     */
    @GetMapping("/clients/mine")
    public Result<List<Map<String, Object>>> myClients(
            @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        if (principal == null) {
            return Result.fail("未登录或令牌无效");
        }
        String userCode = principal.getName();
        List<String> roleCodes = sysRoleMapper.selectRoleCodesByUserCode(userCode);
        return Result.ok(applicationService.listVisibleClients(userCode, roleCodes));
    }
}