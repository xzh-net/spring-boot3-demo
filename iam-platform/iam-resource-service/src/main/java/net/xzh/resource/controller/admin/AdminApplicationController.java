package net.xzh.resource.controller.admin;

import java.util.List;
import java.util.Map;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.entity.IamAppAuthorization;
import net.xzh.resource.entity.IamApplication;
import net.xzh.resource.entity.IamApplicationChannel;
import net.xzh.resource.service.ApplicationService;

/**
 * 应用管理 API（资源中心管理端能力域）.
 * <p>仅面向管理后台（iam-admin-service），路径由 /api/admin/** 规则保护: Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证
 * 提供应用 / 渠道 / 应用授权三级管理，支撑门户工作台应用目录（方案A：密钥零落库）。
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/applications")
@RequiredArgsConstructor
public class AdminApplicationController {

    private final ApplicationService applicationService;

    // ==================== 应用 ====================

    @GetMapping
    public Result<List<Map<String, Object>>> list() {
        return Result.ok(applicationService.listApplications());
    }

    @PostMapping
    public Result<Void> create(@RequestBody IamApplication application) {
        applicationService.createApplication(application);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody IamApplication application) {
        applicationService.updateApplication(id, application);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        applicationService.deleteApplication(id);
        return Result.ok();
    }

    // ==================== 渠道 ====================

    @GetMapping("/{appId}/channels")
    public Result<List<IamApplicationChannel>> listChannels(@PathVariable Long appId) {
        return Result.ok(applicationService.listChannels(appId));
    }

    @PostMapping("/{appId}/channels")
    public Result<Void> createChannel(@PathVariable Long appId, @RequestBody IamApplicationChannel channel) {
        applicationService.createChannel(appId, channel);
        return Result.ok();
    }

    @PutMapping("/{appId}/channels/{channelId}")
    public Result<Void> updateChannel(@PathVariable Long appId, @PathVariable Long channelId,
                                      @RequestBody IamApplicationChannel channel) {
        applicationService.updateChannel(appId, channelId, channel);
        return Result.ok();
    }

    @DeleteMapping("/{appId}/channels/{channelId}")
    public Result<Void> deleteChannel(@PathVariable Long appId, @PathVariable Long channelId) {
        applicationService.deleteChannel(appId, channelId);
        return Result.ok();
    }

    // ==================== 应用授权 ====================

    @GetMapping("/{appId}/authorizations")
    public Result<List<IamAppAuthorization>> listAuthorizations(@PathVariable Long appId) {
        return Result.ok(applicationService.listAuthorizations(appId));
    }

    @PostMapping("/authorizations")
    public Result<Void> createAuthorization(@RequestBody IamAppAuthorization authorization) {
        applicationService.createAuthorization(authorization);
        return Result.ok();
    }

    @DeleteMapping("/authorizations/{id}")
    public Result<Void> deleteAuthorization(@PathVariable Long id) {
        applicationService.deleteAuthorization(id);
        return Result.ok();
    }
}
