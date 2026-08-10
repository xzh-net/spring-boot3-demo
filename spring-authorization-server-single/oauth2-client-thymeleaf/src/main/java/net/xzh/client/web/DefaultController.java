package net.xzh.client.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 默认页面控制器。
 *
 * <p>仅负责展示首页（已登录用户信息）与登出后跳转页，不调用任何资源服务器接口。</p>
 *
 * @author xzh
 */
@Controller
public class DefaultController {

    /**
     * 首页：展示已登录用户信息。
     * 通过 {@link OidcUser} 注入授权服务器返回的 OIDC 用户声明 (sub/email/name 等)。
     */
    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String index(@AuthenticationPrincipal OidcUser oidcUser, Model model) {
        if (oidcUser != null) {
            model.addAttribute("username", oidcUser.getPreferredUsername() != null
                    ? oidcUser.getPreferredUsername()
                    : oidcUser.getSubject());
            model.addAttribute("email", oidcUser.getEmail());
            model.addAttribute("fullName", oidcUser.getFullName());
            model.addAttribute("subject", oidcUser.getSubject());
            model.addAttribute("claims", oidcUser.getClaims());
        }
        return "index";
    }

    /**
     * 登出后展示的静态页 (无需认证，已在 SecurityConfig 中放行)。
     */
    @GetMapping("/logged-out")
    public String loggedOut() {
        return "logged-out";
    }
}
