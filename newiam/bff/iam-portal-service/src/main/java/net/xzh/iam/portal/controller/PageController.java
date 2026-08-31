package net.xzh.iam.portal.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 页面跳转控制器.
 * <p>
 * 处理 OAuth2 登录成功后的跳转。前后端分离架构下, iam-portal-service 不持有任何页面,
 * 登出完成页由 iam-portal-web 前端 (8000) 处理。
 */
@Controller
public class PageController {

    /**
     * OAuth2 登录成功后重定向到前端门户.
     * <p>
     * Spring Security OAuth2Login defaultSuccessUrl 指向这里,
     * 然后重定向到 iam-portal-web 前端 (8000) 的门户首页。
     */
    @GetMapping("/api/auth/callback-success")
    public String callbackSuccess() {
        return "redirect:http://localhost:8200/portal.html";
    }
}
