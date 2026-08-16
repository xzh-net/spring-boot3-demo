package net.xzh.resource.controller.internal;

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
 * 内部用户关联数据清理接口 (资源中心服务间内部能力域).
 * <p>
 * 仅供认证中心（iam-authorization-server）M2M 调用，删除 {@code sys_user} 时
 * 联动清理跨库孤儿数据：
 * <ul>
 *   <li>{@code sys_user_role} — 用户的角色绑定 (user_code);</li>
 *   <li>{@code iam_app_authorization} — subject_type=USER 的主体授权 (subject_id=user_code)。</li>
 * </ul>
 * 安全约束 (同 D6): 由 {@code PORTAL_SERVICE_TOKEN} (门户服务凭证) 把关, 仅允许 client_credentials 服务 token 访问。
 */
@Slf4j
@RestController
@RequestMapping("/api/internal")
@RequiredArgsConstructor
public class InternalUserCleanupController {

    private final RbacService rbacService;
    private final ApplicationService applicationService;

    /**
     * 删除某业务用户编码 (user_code) 在资源中心的全部关联数据.
     * <p>响应: {@code {userCode, roleBindingsDeleted, authorizationsDeleted}}
     */
    @DeleteMapping("/user/{userCode}/data")
    public Result<Map<String, Object>> deleteUserData(@PathVariable String userCode) {
        int roleBindings = rbacService.deleteUserRoleBindings(userCode);
        int authorizations = applicationService.deleteUserAuthorizations(userCode);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("userCode", userCode);
        data.put("roleBindingsDeleted", roleBindings);
        data.put("authorizationsDeleted", authorizations);
        log.info("[internal] 清理用户关联数据 userCode={}, roleBindings={}, authorizations={}",
                userCode, roleBindings, authorizations);
        return Result.ok(data);
    }
}