package net.xzh.authserver.controller.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/")
    public String root() {
        return "forward:/login.html";
    }

    @GetMapping("/admin")
    public String adminRoot() {
        return "forward:/admin/index.html";
    }

    @GetMapping("/portal")
    public String portal() {
        return "forward:/portal.html";
    }
}
