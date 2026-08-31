package net.xzh.iam.open.controller.capability;

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
import net.xzh.iam.common.Result;

/**
 * 开放能力 API (开放平台能力开放域, 面向三方业务客户端).
 * <p>
 * 由旧资源中心 capability 域迁入: 经 iam_api_capability 登记能力 +
 * iam_capability_subscription 订阅准入。注意: 开放响应不再回显平台内部 RBAC
 * 角色/权限 (三方无权感知平台内权限模型), 仅回显调用者身份与令牌元数据。
 * </p>
 */
@RestController
@RequestMapping("/api/capability/contacts")
@RequiredArgsConstructor
public class CapabilityController {

    private static final List<Map<String, Object>> CONTACTS = List.of(
            Map.of("id", 1, "name", "张三", "phone", "13800000001", "email", "zhangsan@example.com", "department", "研发部"),
            Map.of("id", 2, "name", "李四", "phone", "13800000002", "email", "lisi@example.com", "department", "产品部"),
            Map.of("id", 3, "name", "王五", "phone", "13800000003", "email", "wangwu@example.com", "department", "设计部"),
            Map.of("id", 4, "name", "赵六", "phone", "13800000004", "email", "zhaoliu@example.com", "department", "市场部"),
            Map.of("id", 5, "name", "钱七", "phone", "13800000005", "email", "qianqi@example.com", "department", "人力资源部")
    );

    /** 能力: contact:query (iam_api_capability.capability_code) */
    @GetMapping
    public Result<Map<String, Object>> list(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
        Map<String, Object> result = new HashMap<>();
        String userCode = principal.getAttribute("sub");
        result.put("requested_by", userCode);
        result.put("aud", principal.getAttribute("aud"));
        result.put("scope", principal.getAttribute("scope"));

        result.put("userCode", userCode);

        result.put("contacts", CONTACTS);
        return Result.ok(result);
    }

    /** 能力: contact:detail */
    @GetMapping("/{id}")
    public Result<Map<String, Object>> get(@PathVariable int id) {
        return CONTACTS.stream()
                .filter(c -> (int) c.get("id") == id)
                .findFirst()
                .map(Result::ok)
                .orElse(Result.fail(404, "not found"));
    }
}