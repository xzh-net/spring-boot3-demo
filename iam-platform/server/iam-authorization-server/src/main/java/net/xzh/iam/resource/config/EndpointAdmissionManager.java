package net.xzh.iam.resource.config;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.EndpointPolicyService;
import net.xzh.iam.resource.service.EndpointPolicyService.Rule;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 表驱动接口准入路由器 (AuthorizationManager, 实时直查模式).
 * <p>
 * 三档模型 (资源链仅接管三前缀):
 * <ul>
 *   <li><b>每请求 Fail-Closed</b>: 准入查询/权限解析异常一律拒绝, 绝不放行;</li>
 *   <li><b>表内</b> (每请求直查 DB): 档位行按 policy_type 裁决, PERMISSION 行按权限码组合 (ALL/ANY) 裁决
 *       (PERMISSION 行=现查权限表的当前权限码, 改码零窗口; 档位行为常量)。客户端维度隔离由令牌双维交集承担, 无独立白名单闸;</li>
 *   <li><b>表外</b> (三前缀其余端点): 一律拒绝 (fail-closed) —— 未配准入行即 403,
 *       补行保存即时生效; 启动漂移告警提示缺行 (配置完整性属运维职责, 但运行时不降级);</li>
 *   <li><b>/permitall/**}: 链层 permitAll, 不经本路由器。</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
public class EndpointAdmissionManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final EndpointPolicyService endpointPolicyService;

    /** 已对未配准入行的路径打过 warn (按路径去重, 防扫描刷日志) */
    private final Set<String> unregisteredWarned = ConcurrentHashMap.newKeySet();

    public EndpointAdmissionManager(EndpointPolicyService endpointPolicyService) {
        this.endpointPolicyService = endpointPolicyService;
    }

    @Override
    public AuthorizationDecision check(java.util.function.Supplier<Authentication> authenticationSupplier,
                                       RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        Authentication auth = authenticationSupplier.get();

        // 实时直查 + 每请求 Fail-Closed: 查询/权限解析异常一律拒绝, 绝不放行
        Rule rule;
        try {
            rule = endpointPolicyService.findRule(method, uri);
        } catch (Exception e) {
            log.error("[Admission] 准入查询失败(拒绝, Fail-Closed) {} {} -> {}", method, uri, e.getMessage());
            return new AuthorizationDecision(false);
        }
        if (rule == null) {
            // 表外 (未配准入行): 一律拒绝 —— fail-closed, 无猜解放行路径 (A-P0-4 方案A)。
            // 启动漂移告警负责提示补行 (EndpointPolicyScanInitializer), 请求侧不再降级认证档;
            // D1 裁定仅保留启动维度 (不阻塞启动), 运行时子句改判为 deny。
            // 按路径去重: 每路径仅首见打 warn, 后续降 debug, 防扫描刷日志
            if (unregisteredWarned.add(uri)) {
                log.warn("[Admission] 未配准入行(拒绝) {} {} — 请在「资源准入」页补行", method, uri);
            } else {
                log.debug("[Admission] 未配准入行(拒绝) {} {} — 请在「资源准入」页补行", method, uri);
            }
            return new AuthorizationDecision(false);
        }

        if (!rule.enabled()) {
            // status=0 停用行: 准入直接拒绝 (deny), 不再降级认证档
            log.warn("[Admission] 端点已停用(拒绝) {} {} ({})", method, uri, rule.path());
            return new AuthorizationDecision(false);
        }

        boolean allowed = decide(rule, method, uri, auth);
        log.debug("[Admission] {} {} -> {} = {}", method, uri,
                rule.band() != null ? rule.band()
                        : rule.logic() + "(" + String.join(",", rule.requiredCodes()) + ")",
                allowed);
        return new AuthorizationDecision(allowed);
    }

    private boolean decide(Rule rule, String method, String uri, Authentication auth) {
        // 档位行: 按档位裁决
        if (rule.band() != null) {
            return switch (rule.band()) {
                case EndpointPolicyService.AUTH_PERMIT_ALL -> true;
                case EndpointPolicyService.AUTH_AUTHENTICATED -> authenticated(auth);
                default -> false; // 未知档位 → 拒绝 (防御, Fail-Closed)
            };
        }
        // PERMISSION 行: ALL=同时具备 / ANY=任一满足
        if (!authenticated(auth)) {
            return false;
        }
        List<String> codes = rule.requiredCodes();
        if (codes == null || codes.isEmpty()) {
            return false; // PERMISSION 行无绑定 → 拒绝 (防御, 校验/告警层已覆盖)
        }
        if (EndpointPolicyService.LOGIC_ANY.equals(rule.logic())) {
            return codes.stream().anyMatch(c -> hasAuthority(auth, c));
        }
        return codes.stream().allMatch(c -> hasAuthority(auth, c)); // ALL (默认)
    }

    private boolean authenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated();
    }

    private boolean hasAuthority(Authentication auth, String authority) {
        return auth.getAuthorities().stream().anyMatch(a -> authority.equals(a.getAuthority()));
    }
}