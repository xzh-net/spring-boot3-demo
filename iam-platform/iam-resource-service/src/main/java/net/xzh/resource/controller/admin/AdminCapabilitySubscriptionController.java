package net.xzh.resource.controller.admin;

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
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.common.Result;
import net.xzh.resource.entity.IamCapabilitySubscription;
import net.xzh.resource.service.CapabilityService;

/**
 * 开放能力订阅管理 API (资源中心管理端能力域).
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/capability-subscriptions")
@RequiredArgsConstructor
public class AdminCapabilitySubscriptionController {

    private final CapabilityService capabilityService;

    @GetMapping
    public Result<List<IamCapabilitySubscription>> list(
            @RequestParam(required = false) String capabilityCode,
            @RequestParam(required = false) String clientId) {
        return Result.ok(capabilityService.listSubscriptions(capabilityCode, clientId));
    }

    @PostMapping
    public Result<Void> create(@RequestBody IamCapabilitySubscription subscription) {
        capabilityService.createSubscription(subscription);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody IamCapabilitySubscription subscription) {
        capabilityService.updateSubscription(id, subscription);
        return Result.ok();
    }

    /** 取消订阅 (软置 status=0 + revoke_time, 不物理删除) */
    @DeleteMapping("/{id}")
    public Result<Void> revoke(@PathVariable Long id) {
        capabilityService.revokeSubscription(id);
        return Result.ok();
    }
}