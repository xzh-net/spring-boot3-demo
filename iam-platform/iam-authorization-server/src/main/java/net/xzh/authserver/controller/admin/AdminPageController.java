package net.xzh.authserver.controller.admin;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 管理后台页面路由控制器.
 * <p>
 * 将原 static/admin/ 下的静态 HTML 迁移到 templates/admin/ 后,
 * 通过此控制器统一渲染 Thymeleaf 模板, 避免页面被直接作为静态资源访问。
 * <p>
 * 安全保障: 所有 /admin/** 路径由 Order(3) adminSecurityFilterChain 拦截,
 * 未认证用户访问时会重定向到 /admin/login.html。
 */
@Controller
public class AdminPageController {

    /** 在线管理页面 */
    @GetMapping("/admin/online")
    public String online() {
        return "admin/online";
    }

    /** 系统监控页面 */
    @GetMapping("/admin/monitor")
    public String monitor() {
        return "admin/monitor";
    }

    /** 管理员登录页 (permitAll, 由 SecurityFilterChain 放行) */
    @GetMapping("/admin/login.html")
    public String login() {
        return "admin/login";
    }

    /** 管理后台首页 */
    @GetMapping("/admin/index")
    public String index() {
        return "admin/index";
    }
}
