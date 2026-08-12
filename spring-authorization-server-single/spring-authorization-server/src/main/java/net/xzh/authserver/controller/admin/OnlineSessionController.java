package net.xzh.authserver.controller.admin;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.service.AuthSessionService;
import net.xzh.authserver.vo.OnlineUserVO;
import net.xzh.authserver.vo.SsoSessionVO;

/**
 * 在线用户与会话管理 API (设计文档 §9).
 * <p>
 * 提供统一层级视图 (User → SSO Session → Client Session) 的管理端点,
 * 与现有 {@link UserController} 的 /admin/user/api/... 端点并存, 互不影响.
 *
 * <h3>端点列表</h3>
 * <ul>
 *   <li>GET  /admin/online/users          — 统一在线用户列表</li>
 *   <li>GET  /admin/users/{id}/sessions   — 用户会话层级视图 (SSO 会话 + 嵌套客户端会话)</li>
 *   <li>POST /admin/users/{id}/logout     — 按用户踢下线 (撤销所有 SSO 会话 + 客户端会话)</li>
 *   <li>POST /admin/sessions/{id}/logout  — 按 SSO 会话踢下线 (仅撤销指定 SSO 会话及其客户端会话)</li>
 * </ul>
 */
@Slf4j
@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class OnlineSessionController {

    private final AuthSessionService authSessionService;

    /**
     * 统一在线用户列表.
     * <p>
     * 合并 SSO 会话 (HttpSession) 和客户端会话 (OAuth2Authorization) 数据,
     * 返回每个在线用户的会话数和涉及的客户端.
     */
    @GetMapping("/online/users")
    @ResponseBody
    public Result<List<OnlineUserVO>> onlineUsers() {
        return Result.ok(authSessionService.listOnlineUsersUnified());
    }

    /**
     * 指定用户的会话层级视图.
     * <p>
     * 返回该用户的所有 SSO 会话, 每个 SSO 会话下嵌套其关联的客户端会话.
     *
     * @param id 用户 ID (sys_user.id)
     */
    @GetMapping("/users/{id}/sessions")
    @ResponseBody
    public Result<List<SsoSessionVO>> userSessions(@PathVariable Long id) {
        return Result.ok(authSessionService.listSsoSessionsByUserId(id));
    }

    /**
     * 按用户踢下线.
     * <p>
     * 撤销该用户的所有 SSO 会话 (HttpSession) 和客户端会话 (OAuth2 授权),
     * 效果: 所有设备退出.
     *
     * @param id 用户 ID (sys_user.id)
     * @return 被撤销的客户端会话数
     */
    @PostMapping("/users/{id}/logout")
    @ResponseBody
    public Result<Integer> logoutUser(@PathVariable Long id) {
        int kicked = authSessionService.revokeUserAllById(id);
        log.info("[OnlineSessionController] 管理员按用户踢下线 userId={}, 撤销会话数={}", id, kicked);
        return Result.ok(kicked);
    }

    /**
     * 按 SSO 会话踢下线.
     * <p>
     * 仅终止指定的 SSO 会话及其关联的客户端会话, 该用户其他设备的 SSO 会话保持不变.
     *
     * @param id SSO 会话 ID (HttpSession ID)
     */
    @PostMapping("/sessions/{id}/logout")
    @ResponseBody
    public Result<Boolean> logoutSession(@PathVariable String id) {
        boolean ok = authSessionService.revokeSsoSession(id);
        log.info("[OnlineSessionController] 管理员按会话踢下线 ssoSessionId={}, result={}", id, ok);
        return Result.ok(ok);
    }
}
