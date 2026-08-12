package net.xzh.authserver.controller.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 认证中心路由控制器.
 * <p>
 * 门户已拆分为独立项目 (portal-app 8000 + portal-server 8080),
 * 认证中心根路径 "/" 重定向到 portal-app 前端。
 * "/login.html" 仍由认证中心提供, 用于 OAuth2 授权流程的用户认证。
 */
@Controller
public class LoginController {

    /** 根路径重定向到 portal-app 前端 (8000) */
    @GetMapping("/")
    public String root() {
        return "redirect:http://localhost:8000/";
    }

    /** 管理后台入口, 渲染 admin/index 模板 */
    @GetMapping("/admin")
    public String adminRoot() {
        return "admin/index";
    }
}
