package net.xzh.authserver.controller.admin;

import lombok.RequiredArgsConstructor;
import net.xzh.authserver.common.Result;
import net.xzh.authserver.entity.OAuth2RegisteredClient;
import net.xzh.authserver.service.ClientService;
import net.xzh.authserver.vo.ClientVO;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/admin/client")
@RequiredArgsConstructor
public class ClientController {

    private final ClientService clientService;

    @GetMapping
    public String page() {
        return "admin/client";
    }

    @GetMapping("/api/list")
    @ResponseBody
    public Result<List<OAuth2RegisteredClient>> list() {
        return Result.ok(clientService.list());
    }

    @GetMapping("/api/{id}")
    @ResponseBody
    public Result<ClientVO> get(@PathVariable String id) {
        ClientVO vo = clientService.get(id);
        if (vo == null) return Result.fail("客户端不存在");
        return Result.ok(vo);
    }

    @PostMapping("/api")
    @ResponseBody
    public Result<String> create(@RequestBody ClientVO vo) {
        String id = clientService.create(vo);
        return Result.ok(id);
    }

    @PutMapping("/api/{id}")
    @ResponseBody
    public Result<Void> update(@PathVariable String id, @RequestBody ClientVO vo) {
        clientService.update(id, vo);
        return Result.ok();
    }

    @DeleteMapping("/api/{id}")
    @ResponseBody
    public Result<Void> delete(@PathVariable String id) {
        clientService.delete(id);
        return Result.ok();
    }

    @PostMapping("/api/{id}/reset-secret")
    @ResponseBody
    public Result<String> resetSecret(@PathVariable String id) {
        String newSecret = clientService.resetSecret(id);
        return Result.ok(newSecret);
    }
}
