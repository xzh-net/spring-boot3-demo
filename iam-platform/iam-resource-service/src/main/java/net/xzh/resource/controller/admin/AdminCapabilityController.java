package net.xzh.resource.controller.admin;

import java.util.List;

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
import net.xzh.resource.entity.IamApiCapability;
import net.xzh.resource.service.CapabilityService;

/**
 * 开放能力登记管理 API (资源中心管理端能力域).
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/capabilities")
@RequiredArgsConstructor
public class AdminCapabilityController {

    private final CapabilityService capabilityService;

    @GetMapping
    public Result<List<IamApiCapability>> list() {
        return Result.ok(capabilityService.listCapabilities());
    }

    @PostMapping
    public Result<Void> create(@RequestBody IamApiCapability capability) {
        capabilityService.createCapability(capability);
        return Result.ok();
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable Long id, @RequestBody IamApiCapability capability) {
        capabilityService.updateCapability(id, capability);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable Long id) {
        capabilityService.deleteCapability(id);
        return Result.ok();
    }
}