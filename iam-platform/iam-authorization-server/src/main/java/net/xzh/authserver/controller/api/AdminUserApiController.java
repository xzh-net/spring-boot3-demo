package net.xzh.authserver.controller.api;

import java.util.List;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.service.AuthSessionService;
import net.xzh.authserver.service.UserService;
import net.xzh.authserver.vo.SsoSessionVO;

/**
 * 三域管理 API — 用户域 (/api/admin/users).
 * <p>
 * 认证中心「用户管理」面向 iam_identity.sys_user 的 REST 接口,
 * 经 Order(2) 安全链保护 (Bearer + ROLE_ADMIN), 供 admin-service / 管理前端调用。
 * </p>
 */
@RestController
@RequestMapping("/api/admin/users")
@RequiredArgsConstructor
public class AdminUserApiController {

    private final UserService userService;
    private final AuthSessionService authSessionService;

    @GetMapping
    public Result<List<SysUser>> list() {
        return Result.ok(userService.list());
    }

    @GetMapping("/{id}")
    public Result<SysUser> get(@PathVariable Long id) {
        SysUser user = userService.get(id);
        if (user == null) {
            return Result.fail("用户不存在");
        }
        return Result.ok(user);
    }

    @PostMapping
    public Result<Void> create(@RequestBody SysUser user) {
        userService.create(user);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody SysUser user) {
        userService.update(id, user);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        return Result.ok();
    }

    @PutMapping("/{id}/enable")
    public Result<Void> enable(@PathVariable Long id, @RequestParam boolean enabled) {
        userService.enable(id, enabled);
        return Result.ok();
    }

    @PostMapping("/{id}/reset-password")
    public Result<Void> resetPassword(@PathVariable Long id) {
        userService.resetPassword(id);
        return Result.ok();
    }

    @GetMapping("/{id}/sessions")
    public Result<List<SsoSessionVO>> sessions(@PathVariable Long id) {
        return Result.ok(authSessionService.listSsoSessionsByUserId(id));
    }

    @DeleteMapping("/{id}/sessions")
    public Result<Integer> kickAll(@PathVariable Long id) {
        int kicked = authSessionService.revokeUserAllById(id);
        return Result.ok(kicked);
    }
}
