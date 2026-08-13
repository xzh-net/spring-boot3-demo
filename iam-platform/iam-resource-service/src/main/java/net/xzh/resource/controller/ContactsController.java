package net.xzh.resource.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.xzh.resource.common.Result;
import net.xzh.resource.entity.SysUser;
import net.xzh.resource.service.PermissionService;

/**
 * 通讯录 API (数据仍为硬编码).
 * <p>
 * 身份与权限对应: 从内省 token 的 sub (用户名) 解析出数据库中的用户身份,
 * 并通过 RBAC 表查询其角色与权限, 一并返回给调用方。
 * </p>
 */
@RestController
@RequestMapping("/api/contacts")
@RequiredArgsConstructor
public class ContactsController {

    private static final List<Map<String, Object>> CONTACTS = List.of(
            Map.of("id", 1, "name", "张三", "phone", "13800000001", "email", "zhangsan@example.com", "department", "研发部"),
            Map.of("id", 2, "name", "李四", "phone", "13800000002", "email", "lisi@example.com", "department", "产品部"),
            Map.of("id", 3, "name", "王五", "phone", "13800000003", "email", "wangwu@example.com", "department", "设计部"),
            Map.of("id", 4, "name", "赵六", "phone", "13800000004", "email", "zhaoliu@example.com", "department", "市场部"),
            Map.of("id", 5, "name", "钱七", "phone", "13800000005", "email", "qianqi@example.com", "department", "人力资源部")
    );

    private final PermissionService permissionService;

    @GetMapping
    public Result<Map<String, Object>> list(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> result = new HashMap<>();
        String username = principal.getAttribute("sub");
        result.put("requested_by", username);
        result.put("aud", principal.getAttribute("aud"));
        result.put("scope", principal.getAttribute("scope"));

        // 身份与权限对应: sub → sys_user → RBAC 角色/权限
        SysUser user = permissionService.findByUsername(username);
        if (user != null) {
            result.put("user", Map.of(
                    "id", user.getId(),
                    "username", user.getUsername(),
                    "nickname", user.getNickname(),
                    "role", user.getRole(),
                    "enabled", user.getEnabled()));
            result.put("roles", permissionService.findRoleCodes(username));
            result.put("permissions", permissionService.findPermissions(username));
        } else {
            // client_credentials 等非用户主体: 无数据库身份
            result.put("user", null);
            result.put("roles", List.of());
            result.put("permissions", List.of());
        }

        result.put("contacts", CONTACTS);
        return Result.ok(result);
    }

    @GetMapping("/{id}")
    public Result<Map<String, Object>> get(@PathVariable int id) {
        return CONTACTS.stream()
                .filter(c -> (int) c.get("id") == id)
                .findFirst()
                .map(Result::ok)
                .orElse(Result.fail(404, "not found"));
    }
}