package net.xzh.resource.controller.admin;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.service.ApplicationService;
import net.xzh.resource.service.RbacService;

/**
 * 用户关联数据清理接口 (资源中心管理端能力域).
 * <p>
 * 按开发规范 (设计说明书 §23.4) 管理写操作归 {@code /api/admin/**} 管理端能力
 * ({@code controller/admin} 分包), 由<b>管理 M2M 服务凭证</b>把关:
 * 认证中心 (iam-authorization-server) 以 {@code admin-m2m} 客户端 client_credentials
 * 换取服务令牌, 资源中心内省时注入 {@code ADMIN_SERVICE_TOKEN}, 即可代表「删除用户」这一
 * 管理动作在此联动清理该用户 (user_code) 的跨库孤儿数据:
 * <ul>
 *   <li>{@code sys_user_role} — 用户的角色绑定 (user_code);</li>
 *   <li>{@code iam_app_authorization} — subject_type=USER 的主体授权 (subject_id=user_code)。</li>
 * </ul>
 * 管理台管理员令牌 (admin-app 签发, 含 ADMIN_SERVICE_TOKEN) 同样可调, 幂等清理。
 * 与 {@code controller/internal} 的只读角色内省 (对标认证中心内省接口) 职责分离。
 */
@Slf4j
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminUserDataController {

    private final RbacService rbacService;
    private final ApplicationService applicationService;

    /**
     * 删除某业务用户编码 (user_code) 在资源中心的全部关联数据.
     * <p>响应: {@code {userCode, roleBindingsDeleted, authorizationsDeleted}}
     */
    @DeleteMapping("/users/{userCode}/data")
    public Result<Map<String, Object>> deleteUserData(@PathVariable String userCode) {
        int roleBindings = rbacService.deleteUserRoleBindings(userCode);
        int authorizations = applicationService.deleteUserAuthorizations(userCode);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("userCode", userCode);
        data.put("roleBindingsDeleted", roleBindings);
        data.put("authorizationsDeleted", authorizations);
        log.info("[admin] 清理用户关联数据 userCode={}, roleBindings={}, authorizations={}",
                userCode, roleBindings, authorizations);
        return Result.ok(data);
    }
}