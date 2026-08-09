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

    // ========= 在线用户相关 =========

    @GetMapping("/api/online")
    @ResponseBody
    public Result<List<Map<String, Object>>> onlineUsers() {
        return Result.ok(authSessionService.listOnlineUsers());
    }

    @GetMapping("/api/online/{username}")
    @ResponseBody
    public Result<List<?>> userSessions(@PathVariable String username) {
        return Result.ok(authSessionService.listSessionsByPrincipal(username));
    }

    @DeleteMapping("/api/online/{username}")
    @ResponseBody
    public Result<Integer> kickUser(@PathVariable String username) {
        int kicked = authSessionService.revokeUserAll(username);
        return Result.ok(kicked);
    }

    @DeleteMapping("/api/session/{authorizationId}")
    @ResponseBody
    public Result<Boolean> kickSession(@PathVariable String authorizationId) {
        boolean ok = authSessionService.revokeSession(authorizationId);
        return Result.ok(ok);
    }
}
