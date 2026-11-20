package net.xzh.iam.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.service.LoginAdmissionService;

/**
 * 设备码激活入口.
 * <p>
 * 设备码流程中, 用户需在浏览器访问此页面输入 user_code 进行设备授权.
 * 路由 /activate 落到 Order(5) deviceVerificationSecurityFilterChain, 使用独立的
 * DEVICE_SECURITY_CONTEXT, 不污染 OAuth2 登录会话 (OAUTH2_SECURITY_CONTEXT).
 * <p>
 * 如果 URL 已携带 user_code (如 verification_uri_complete), 直接重定向到 SAS 验证端点.
 * <p>
 * <b>登录准入前置</b> (client_login_policy, fail-closed): 该客户端未放行当前主体时,
 * 立即 302 到 {@code login.html?error=access_denied} —— 与授权码流同文案同体验,
 * 用户走不到 consent / 成功页, 从用户视角「该场景不存在」, 避免
 * 「浏览器显示设备授权成功、设备轮询却拒绝」的矛盾提示。
 * 换票阶段 {@code DeviceCodeGrantAuthenticationProvider} 仍保留同判据闸作纵深防御.
 * <p>
 * 设备验证成功后, SAS 的 SimpleUrlAuthenticationSuccessHandler 重定向到 /?success,
 * 本控制器匹配该请求, 清除 DEVICE_SECURITY_CONTEXT (一次性认证), 渲染 device-activated 成功页面.
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class DeviceActivateController {

    /** 设备验证链的 SecurityContext 在 HttpSession 中的 key, 与 AuthorizationServerConfig.DEVICE_CONTEXT_KEY 一致 */
    private static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

    /** user_code 的令牌类型 (与 SAS OAuth2DeviceVerificationAuthenticationProvider 内部常量一致) */
    private static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType("user_code");

    /**
     * SavedRequest 缓存 — 拒绝时存下原始请求, 使用户在错误页重新登录后能回到原处重新判定.
     * <p>
     * 不存的话: 拒绝 302 (普通重定向, 不经 AuthenticationEntryPoint) 不会保存请求,
     * 重新登录后无 SavedRequest → 走 defaultSuccessUrl "/" → 被 LoginController 送进门户页.
     * 实例无状态 (存储用固定 session attribute key), 各处独立 new 亦兼容 Spring Security 默认 handler.
     */
    private static final HttpSessionRequestCache REQUEST_CACHE = new HttpSessionRequestCache();

    private final OAuth2AuthorizationService authorizationService;
    private final RegisteredClientRepository registeredClientRepository;
    private final LoginAdmissionService loginAdmissionService;

    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode,
                           Authentication auth,
                           HttpServletRequest request,
                           HttpServletResponse response) {
        if (userCode != null && !userCode.isBlank()) {
            // 【登录准入·前置】准入表未命中 → 踢到登录页 (与授权码流同文案), 不进 SAS 验证端点
            if (!admitted(userCode, auth)) {
                log.info("[签发准入] 设备激活拒绝 (准入表未命中): 设备userCode={}, 用户={}",
                        userCode, auth != null ? auth.getName() : "anonymous");
                // 存 SavedRequest: 否则拒绝 302 (普通重定向) 不留恢复点, 用户在错误页重新登录后
                // 无 SavedRequest 可恢复 → 走 defaultSuccessUrl "/" → 被 LoginController 送进门户页
                REQUEST_CACHE.saveRequest(request, response);
                // 带 type=device: 错误页 form.action 才会指向 /device-login (链2),
                // 登录写 DEVICE_SECURITY_CONTEXT — 链2 只读该 key, 否则读不到登录态会要求二次登录
                return "redirect:/login.html?type=device&error=access_denied";
            }
            return "redirect:/oauth2/device/verify?user_code=" + userCode;
        }
        return "device-activate";
    }

    /**
     * 该用户能否激活此设备 (client_login_policy 裁决, fail-closed).
     * <p>
     * 查不到 user_code 对应授权 / 客户端时<b>放行</b> — 交由 SAS 验证端点给出更精确的
     * invalid_grant, 此处只在「能判定」时判定, 不吞掉协议层错误。
     * 判定过程异常 → 拒绝 (fail-closed, 与平台关键设计裁定一致)。
     */
    private boolean admitted(String deviceUserCode, Authentication auth) {
        // 未登录: 交给设备验证链的认证流程 (会先跳登录页), 不在此处越权裁决
        if (auth == null || !auth.isAuthenticated()) {
            return true;
        }
        try {
            OAuth2Authorization authorization = authorizationService
                    .findByToken(deviceUserCode, USER_CODE_TOKEN_TYPE);
            if (authorization == null) {
                return true;
            }
            RegisteredClient client = registeredClientRepository
                    .findById(authorization.getRegisteredClientId());
            if (client == null) {
                return true;
            }
            // principal name 即业务用户编码 user_code
            return loginAdmissionService.canLogin(client.getClientId(), auth.getName());
        } catch (Exception e) {
            log.error("[签发准入] 设备激活准入判定异常 (fail-closed 拒绝): userCode={}, err={}",
                    deviceUserCode, e.getMessage());
            return false;
        }
    }

    /**
     * 设备验证成功页面.
     * <p>
     * SAS 默认 successHandler 重定向到 /?success, 此方法匹配 params=success 优先于
     * LoginController 的 @GetMapping("/").
     * <p>
     * 渲染成功页前, 清除 DEVICE_SECURITY_CONTEXT — 设备验证是一次性动作, 不残留登录态.
     * 如果用户此前已通过 OAuth2 登录 (OAUTH2_SECURITY_CONTEXT), 登录会话不受影响.
     */
    @GetMapping(value = "/", params = "success")
    public String deviceActivated(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(DEVICE_CONTEXT_KEY);
        }
        return "device-activated";
    }
}
