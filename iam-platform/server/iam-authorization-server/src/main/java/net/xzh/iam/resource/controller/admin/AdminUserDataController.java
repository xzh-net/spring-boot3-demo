package net.xzh.iam.resource.controller.admin;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import net.xzh.iam.resource.service.ApplicationService;
import net.xzh.iam.resource.service.RbacService;

/**
 * 用户关联数据清理接口 (管理端能力域).
 * <p>
 * 按开发规范管理写操作归 {@code /api/admin/**} 管理端能力 ({@code controller/admin} 分包),
 * 由 {@code ADMIN_SERVICE_TOKEN} 把关。清理目标:
 * <ul>
 *   <li>{@code sys_user_role} — 用户的角色绑定 (user_code);</li>
 *   <li>{@code iam_app_authorization} — subject_type=USER 的主体授权 (subject_id=user_code)。</li>
 * </ul>
 * 管理台管理员令牌 (admin-app 签发, 角色含 ADMIN → 注入 ADMIN_SERVICE_TOKEN) 可调, 幂等。
 * <b>历史说明</b>: 原调用方为跨服务链路 (认证中心以 {@code admin-m2m} client_credentials 换服务令牌
 * 联动清理), 合并单服务后删除链已本地化 ({@code UserService} 直调 {@code RbacService} /
 * {@code ApplicationService}), admin-m2m 凭证通道已退役, 本接口保留为管理端手工/运维幂等清理入口。
 */
@Slf4j
@RestController
@RequestMapping("/admin")
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