package net.xzh.iam.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 认证中心路由控制器.
 * <p>
 * "/login.html" 由认证中心提供, 用于 OAuth2 授权流程的用户认证。
 * <p>
 * <b>根路径 "/" = 门户的统一入口 (直接 URL 登录场景):</b>
 * 直接访问认证中心 (无 SavedRequest) 时, 302 到门户 BFF 的 OAuth2 授权发起端点,
 * 使「直登」在结构上等同于「从门户发起的 OAuth2 登录」:
 * <ol>
 *   <li>8080/oauth2/authorization/portal-app-oidc 自动完成中转 (生成 PKCE/state 后
 *       302 回 /oauth2/authorize), 用户无感;</li>
 *   <li>authorize 未登录 → login.html (authorize 请求已存 SavedRequest);</li>
 *   <li>登录成功 → SavedRequest 恢复 → 签发准入闸判定:</li>
 * </ol>
 * PORTAL 用户 → 发码 → 回 8080 换票 → 落已登录态门户 (8000/portal.html);
 * 其他角色 (如 admin) → 准入拒绝 → login.html?error=access_denied
 * (管理端走 8001 自己的入口, 不面向门户用户)。
 * <p>
 * 注: 本路径不属任何安全链 securityMatcher, 请求绕过过滤器链, 此处拿不到
 * SecurityContext — 分流与准入均不依赖本控制器。
 * "/?success" (设备激活成功页) 由 DeviceActivateController 以 params="success"
 * 更具体的映射优先匹配, 不经过本方法。
 */
@Controller
public class LoginController {

    /**
     * 根路径重定向到门户 BFF 的 OAuth2 授权发起端点 (portal-app, 带 PKCE)。
     * <p>
     * 不直拼 /oauth2/authorize — 必须经 8080 由 BFF 生成 state/code_challenge
     * 并暂存 verifier, 否则回调换票链路断裂。落点写死白名单, 防开放重定向。
     */
    @GetMapping("/")
    public String root() {
        return "redirect:http://localhost:8080/oauth2/authorization/portal-app-oidc";
    }
}
