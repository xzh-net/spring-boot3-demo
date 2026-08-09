package net.xzh.authserver.controller.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 设备码激活入口.
 * <p>
 * 设备码流程中, 用户需在浏览器访问此页面输入 user_code 进行设备授权.
 * 路由 /activate 落到 Order(5) deviceVerificationSecurityFilterChain, 使用独立的
 * DEVICE_SECURITY_CONTEXT, 不污染门户会话 (PORTAL_SECURITY_CONTEXT).
 * <p>
 * 如果 URL 已携带 user_code (如 verification_uri_complete), 直接重定向到 SAS 验证端点.
 * <p>
 * 设备验证成功后, SAS 的 SimpleUrlAuthenticationSuccessHandler 重定向到 /?success,
 * 本控制器匹配该请求, 清除 DEVICE_SECURITY_CONTEXT (一次性认证), 渲染 device-activated 成功页面.
 */
@Controller
public class DeviceActivateController {

    /** 设备验证链的 SecurityContext 在 HttpSession 中的 key, 与 AuthorizationServerConfig.DEVICE_CONTEXT_KEY 一致 */
    private static final String DEVICE_CONTEXT_KEY = "DEVICE_SECURITY_CONTEXT";

    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode) {
        if (userCode != null && !userCode.isBlank()) {
            return "redirect:/oauth2/device/verify?user_code=" + userCode;
        }
        return "device-activate";
    }

    /**
     * 设备验证成功页面.
     * <p>
     * SAS 默认 successHandler 重定向到 /?success, 此方法匹配 params=success 优先于
     * LoginController 的 @GetMapping("/").
     * <p>
     * 渲染成功页前, 清除 DEVICE_SECURITY_CONTEXT — 设备验证是一次性动作, 不残留登录态.
     * 如果用户此前已登录门户 (PORTAL_SECURITY_CONTEXT), 门户会话不受影响.
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
