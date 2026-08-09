package net.xzh.authserver.controller.api;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/contacts")
public class ContactsController {

    private static final List<Map<String, Object>> CONTACTS = List.of(
            Map.of("id", 1, "name", "张三", "phone", "13800000001", "email", "zhangsan@example.com", "department", "研发部"),
            Map.of("id", 2, "name", "李四", "phone", "13800000002", "email", "lisi@example.com", "department", "产品部"),
            Map.of("id", 3, "name", "王五", "phone", "13800000003", "email", "wangwu@example.com", "department", "设计部"),
            Map.of("id", 4, "name", "赵六", "phone", "13800000004", "email", "zhaoliu@example.com", "department", "市场部"),
            Map.of("id", 5, "name", "钱七", "phone", "13800000005", "email", "qianqi@example.com", "department", "人力资源部")
    );

    @GetMapping
    public Map<String, Object> list(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> result = new HashMap<>();
        // access_token 已改用 Opaque: 身份信息从 introspect 返回的 principal attributes 中取
        // sub 对应登录用户名 (授权码/password 模式) 或 client_id (client_credentials 模式)
        result.put("requested_by", principal.getAttribute("sub"));
        result.put("aud", principal.getAttribute("aud"));
        result.put("scope", principal.getAttribute("scope"));
        result.put("contacts", CONTACTS);
        return result;
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable int id) {
        return CONTACTS.stream()
                .filter(c -> (int) c.get("id") == id)
                .findFirst()
                .orElse(Map.of("error", "not found"));
    }
}
