package net.xzh.iam.auth.controller.api;

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
import net.xzh.iam.common.Result;
import net.xzh.iam.auth.entity.OAuth2RegisteredClient;
import net.xzh.iam.auth.service.ClientService;
import net.xzh.iam.auth.vo.ClientVO;

/**
 * 三域管理 API — 客户端域 (/api/internal/identity/clients).
 * <p>
 * 认证中心「客户端管理」面向 oauth2_registered_client 的 REST 接口,
 * 经 Order(2) 安全链保护 (Bearer + ADMIN_SERVICE_TOKEN 管理服务凭证)。
 * </p>
 */
@RestController
@RequestMapping("/api/internal/identity/clients")
@RequiredArgsConstructor
public class AdminClientApiController {

    private final ClientService clientService;

    @GetMapping
    public Result<List<OAuth2RegisteredClient>> list() {
        return Result.ok(clientService.list());
    }

    @GetMapping("/{id}")
    public Result<ClientVO> get(@PathVariable String id) {
        ClientVO vo = clientService.get(id);
        if (vo == null) {
            return Result.fail("客户端不存在");
        }
        return Result.ok(vo);
    }

    @PostMapping
    public Result<String> create(@RequestBody ClientVO vo) {
        return Result.ok(clientService.create(vo));
    }

    @PutMapping("/{id}")
    public Result<Void> update(@PathVariable String id, @RequestBody ClientVO vo) {
        clientService.update(id, vo);
        return Result.ok();
    }

    @DeleteMapping("/{id}")
    public Result<Void> delete(@PathVariable String id) {
        clientService.delete(id);
        return Result.ok();
    }

    @PostMapping("/{id}/reset-secret")
    public Result<String> resetSecret(@PathVariable String id) {
        return Result.ok(clientService.resetSecret(id));
    }
}
