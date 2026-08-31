package net.xzh.iam.auth.controller.api;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import net.xzh.iam.auth.service.AuthSessionService;
import net.xzh.iam.auth.vo.OnlineUserVO;
import net.xzh.iam.auth.vo.SsoSessionVO;

/**
 * 三域管理 API — 会话域 (/api/internal/identity/sessions).
 * <p>
 * 统一在线用户 / 会话层级视图 (User → SSO Session → Client Session) 与强制下线,
 * 经 Order(2) 安全链保护 (Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证)。逻辑复用 {@link AuthSessionService}。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/internal/identity/sessions")
@RequiredArgsConstructor
public class AdminSessionApiController {

    private final AuthSessionService authSessionService;

    @GetMapping("/online")
    public Result<List<OnlineUserVO>> onlineUsers() {
        return Result.ok(authSessionService.listOnlineUsersUnified());
    }

    @GetMapping("/users/{id}")
    public Result<List<SsoSessionVO>> userSessions(@PathVariable Long id) {
        return Result.ok(authSessionService.listSsoSessionsByUserId(id));
    }

    @PostMapping("/users/{id}/logout")
    public Result<Integer> kickUser(@PathVariable Long id) {
        int kicked = authSessionService.revokeUserAllById(id);
        log.info("[AdminSessionApi] 按用户踢下线 userId={}, 撤销会话数={}", id, kicked);
        return Result.ok(kicked);
    }

    @PostMapping("/{ssoSessionId}/logout")
    public Result<Boolean> kickSsoSession(@PathVariable String ssoSessionId) {
        boolean ok = authSessionService.revokeSsoSession(ssoSessionId);
        log.info("[AdminSessionApi] 按 SSO 会话踢下线 ssoSessionId={}, result={}", ssoSessionId, ok);
        return Result.ok(ok);
    }

    @DeleteMapping("/online/{username}")
    public Result<Integer> kickClientUser(@PathVariable String username) {
        int kicked = authSessionService.revokeClientTokensByPrincipal(username);
        log.info("[AdminSessionApi] 按用户撤销客户端令牌 username={}, 撤销数={}", username, kicked);
        return Result.ok(kicked);
    }
}
