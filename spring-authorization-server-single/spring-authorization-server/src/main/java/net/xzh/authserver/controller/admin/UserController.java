package net.xzh.authserver.controller.admin;

import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.RequiredArgsConstructor;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.service.AuthSessionService;
import net.xzh.authserver.service.UserService;

@Controller
@RequestMapping("/admin/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthSessionService authSessionService;

    @GetMapping()
    public String page() {
        return "redirect:/admin/user.html";
    }

    @GetMapping("/api/list")
    @ResponseBody
    public Result<List<SysUser>> list() {
        return Result.ok(userService.list());
    }

    @GetMapping("/api/{id}")
    @ResponseBody
    public Result<SysUser> get(@PathVariable Long id) {
        return Result.ok(userService.get(id));
    }

    @PostMapping("/api")
    @ResponseBody
    public Result<Void> create(@RequestBody SysUser user) {
        userService.create(user);
        return Result.ok();
    }

    @PutMapping("/api/{id}")
    @ResponseBody
    public Result<Void> update(@PathVariable Long id, @RequestBody SysUser user) {
        user.setId(id);
        userService.update(id, user);
        return Result.ok();
    }

    @DeleteMapping("/api/{id}")
    @ResponseBody
    public Result<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return Result.ok();
    }

    @PutMapping("/api/{id}/enable")
    @ResponseBody
    public Result<Void> enable(@PathVariable Long id, @RequestParam boolean enabled) {
        userService.enable(id, enabled);
        return Result.ok();
    }

    @PostMapping("/api/{id}/reset-password")
    @ResponseBody
    public Result<Void> resetPassword(@PathVariable Long id) {
        userService.resetPassword(id);
        return Result.ok();
    }

    // ========= 在线管理相关 (3个选项卡) =========

    /**
     * 管理端在线用户列表。
     */
    @GetMapping("/api/admin/online")
    @ResponseBody
    public Result<List<Map<String, Object>>> adminOnlineUsers() {
        return Result.ok(authSessionService.listAdminOnlineUsers());
    }

    /**
     * 门户端在线用户列表。
     */
    @GetMapping("/api/portal/online")
    @ResponseBody
    public Result<List<Map<String, Object>>> portalOnlineUsers() {
        return Result.ok(authSessionService.listPortalOnlineUsers());
    }

    /**
     * 客户端在线用户列表 (OAuth2 对接进来的用户)。
     */
    @GetMapping("/api/client/online")
    @ResponseBody
    public Result<List<Map<String, Object>>> clientOnlineUsers() {
        return Result.ok(authSessionService.listOnlineUsers());
    }

    /**
     * 指定用户的所有会话明细 (客户端)。
     */
    @GetMapping("/api/client/online/{username}")
    @ResponseBody
    public Result<List<?>> userSessions(@PathVariable String username) {
        return Result.ok(authSessionService.listSessionsByPrincipal(username));
    }

    /**
     * 踢下线单个会话 (HttpSession, 管理端/门户端通用)。
     */
    @DeleteMapping("/api/session/{sessionId}")
    @ResponseBody
    public Result<Boolean> kickHttpSession(@PathVariable String sessionId) {
        boolean ok = authSessionService.revokeHttpSession(sessionId);
        return Result.ok(ok);
    }

    /**
     * 踢下线单个客户端会话 (OAuth2Authorization)。
     */
    @DeleteMapping("/api/client/session/{authorizationId}")
    @ResponseBody
    public Result<Boolean> kickClientSession(@PathVariable String authorizationId) {
        boolean ok = authSessionService.revokeSession(authorizationId);
        return Result.ok(ok);
    }

    /**
     * 踢下线用户全部管理端会话 (仅终止 HttpSession, 不撤销 OAuth2)。
     */
    @DeleteMapping("/api/admin/online/{username}")
    @ResponseBody
    public Result<Integer> kickAdminUser(@PathVariable String username) {
        int kicked = authSessionService.revokeSessionUser(username, true);
        return Result.ok(kicked);
    }

    /**
     * 踢下线用户全部门户端会话 (仅终止 HttpSession, 不撤销 OAuth2)。
     */
    @DeleteMapping("/api/portal/online/{username}")
    @ResponseBody
    public Result<Integer> kickPortalUser(@PathVariable String username) {
        int kicked = authSessionService.revokeSessionUser(username, false);
        return Result.ok(kicked);
    }

    /**
     * 踢下线用户全部客户端会话 (撤销 OAuth2 令牌 + 终止 HttpSession)。
     */
    @DeleteMapping("/api/client/online/{username}")
    @ResponseBody
    public Result<Integer> kickClientUser(@PathVariable String username) {
        int kicked = authSessionService.revokeUserAll(username);
        return Result.ok(kicked);
    }
}
