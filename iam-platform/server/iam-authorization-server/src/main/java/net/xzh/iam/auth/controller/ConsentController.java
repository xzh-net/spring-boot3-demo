package net.xzh.iam.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.entity.SysPermission;
import net.xzh.iam.resource.entity.SysScope;
import net.xzh.iam.resource.mapper.SysPermissionMapper;
import net.xzh.iam.resource.mapper.SysScopeMapper;
import net.xzh.iam.resource.service.LoginAdmissionService;
import net.xzh.iam.resource.service.PermissionService;
import net.xzh.iam.resource.service.ScopeService;

@Slf4j
@Controller
@RequiredArgsConstructor
public class ConsentController {

    private final RegisteredClientRepository registeredClientRepository;
    private final LoginAdmissionService loginAdmissionService;
    private final ScopeService scopeService;
    private final PermissionService permissionService;
    private final SysScopeMapper sysScopeMapper;
    private final SysPermissionMapper sysPermissionMapper;

    /** SavedRequest 缓存 — 拒绝时存下原始请求, 使重新登录后能回到同意页重新判定 (语义同 DeviceActivateController) */
    private static final HttpSessionRequestCache REQUEST_CACHE = new HttpSessionRequestCache();

    @GetMapping("/consent")
    public String consentPage(
            @RequestParam("client_id") String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "user_code", required = false) String userCode,
            Authentication auth,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model) {

        // 【登录准入·兜底】防止直接构造 consent URL 绕过 /activate 的前置判定。
        // 与 DeviceActivateController 同判据 (client_login_policy), 同文案踢回登录页。
        if (auth != null && auth.isAuthenticated()
                && !loginAdmissionService.canLogin(clientId, auth.getName())) {
            log.info("[签发准入] 同意页拒绝 (准入表未命中): 客户端={}, 用户={}", clientId, auth.getName());
            // 存 SavedRequest: 否则重新登录后无恢复点, 会走 defaultSuccessUrl "/" → 门户页
            REQUEST_CACHE.saveRequest(request, response);
            return "redirect:/login.html?error=access_denied";
        }

        // C-2①: 取注册表客户端 (注册名 client_name 展示, 原误传 clientId 导致大标题显示技术标识)
        RegisteredClient client = null;
        try {
            client = registeredClientRepository.findByClientId(clientId);
        } catch (Exception e) {
            log.warn("查询客户端失败 (同意页降级): clientId={}", clientId);
        }

        String effectiveRedirectUri = redirectUri;
        if (effectiveRedirectUri == null || effectiveRedirectUri.isBlank()) {
            if (client != null && !client.getRedirectUris().isEmpty()) {
                effectiveRedirectUri = client.getRedirectUris().iterator().next();
            }
        }

        // C-2②: 请求 scope 列表 — 描述改字典驱动 (sys_scope 展示名), 原 5 词硬编码弃用
        Map<String, String> scopeDict = loadScopeDict();
        Map<String, String> scopeMap = new LinkedHashMap<>();
        if (scope != null && !scope.isBlank()) {
            for (String s : scope.split("\\s+")) {
                scopeMap.put(s, describeScope(s, scopeDict));
            }
        }

        // C-2③⑤: 实际授予 = 注册表 scope 展开 ∩ 用户 RBAC (与自省层同源同公式) —
        //          让用户看见「批了之后到底拿到什么业务权限」, 原页面对封顶结果零可见。
        Map<String, String> granted = computeGrantedCodes(client, auth);

        model.addAttribute("clientName", (client != null && client.getClientName() != null)
                ? client.getClientName() : clientId);
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", effectiveRedirectUri);
        model.addAttribute("responseType", responseType != null ? responseType : "code");
        model.addAttribute("scopes", scopeMap);
        model.addAttribute("scopeList", scopeMap.keySet());
        model.addAttribute("grantedCodes", granted);
        model.addAttribute("state", state);
        model.addAttribute("userCode", userCode);
        // 设备码流程表单提交到 /oauth2/device/verify, 授权码流程提交到 /oauth2/authorize
        model.addAttribute("requestURI",
                (userCode != null && !userCode.isBlank()) ? "/oauth2/device/verify" : "/oauth2/authorize");

        return "consent";
    }

    /** sys_scope 字典 (code → 展示名), 查询失败返回空表 (描述降级原样回显) */
    private Map<String, String> loadScopeDict() {
        try {
            Map<String, String> dict = new LinkedHashMap<>();
            for (SysScope s : sysScopeMapper.selectList(new QueryWrapper<SysScope>())) {
                dict.put(s.getCode(), s.getName());
            }
            return dict;
        } catch (Exception e) {
            log.warn("scope 字典加载失败 (同意页描述降级): {}", e.getMessage());
            return Map.of();
        }
    }

    /**
     * C-2②: scope 描述 = 字典展示名; 字典外 (存量 read/write 占位等) 返回 null 不渲染 desc,
     * 避免 "read => read" 重复回显。业务组 (admin.full 等) 字典有名即显示名, 不再原样抛 key。
     */
    private String describeScope(String scope, Map<String, String> dict) {
        String name = dict.get(scope);
        return (name != null && !name.isBlank()) ? name : null;
    }

    /**
     * C-2③⑤: 实际授予业务码 = expand(注册表 scopes) ∩ 用户 RBAC 码。
     * 与 RedisOpaqueTokenIntrospector 自省层同一公式 — 页面所见即令牌所得。
     * 无用户认证 / 客户端缺失 / 计算异常 → 空表 (页面显示「无业务权限」)。
     */
    private Map<String, String> computeGrantedCodes(RegisteredClient client, Authentication auth) {
        Map<String, String> result = new LinkedHashMap<>();
        if (client == null || auth == null || !auth.isAuthenticated()) {
            return result;
        }
        try {
            Set<String> expansion = scopeService.expandScopeCodes(client.getScopes());
            if (expansion.isEmpty()) {
                return result;   // 无映射 (third.profile/标准 scope) → 业务码为空, fail-closed 语义
            }
            Set<String> userCodes = permissionService.findPermissions(auth.getName());
            Set<String> granted = new LinkedHashSet<>(expansion);
            granted.retainAll(userCodes);
            if (granted.isEmpty()) {
                return result;
            }
            // 码 → 展示名 (一次批量查)
            List<SysPermission> perms = sysPermissionMapper.selectList(
                    new QueryWrapper<SysPermission>().in("code", granted));
            for (SysPermission p : perms) {
                result.put(p.getCode(), p.getName());
            }
        } catch (Exception e) {
            log.warn("实际授予码计算失败 (同意页降级为空): {}", e.getMessage());
        }
        return result;
    }
}
