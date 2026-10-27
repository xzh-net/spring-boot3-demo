package net.xzh.iam.resource.controller.permitall;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * 不需要权限的接口示例 (放行).
 * <p>
 * 仅承载「任何客户端 / 无令牌」均可访问的公开端点, 用于连通性与系统时间自测。
 * 不进入 iam_endpoint_policy 准入表 (播种白名单仅 admin/portal/third 三域),
 * 由 ResourceServerConfig 资源链对 /api/permitall/** 链层 permitAll (免令牌)。
 * </p>
 */
@Slf4j
@RestController
@RequestMapping("/api/permitall")
public class TimeController {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * 返回服务端当前时间 (放行端点, 无认证要求).
     */
    @GetMapping("/time")
    public Result<Map<String, Object>> time() {
        LocalDateTime now = LocalDateTime.now();
        return Result.ok(Map.of(
                "serverTime", now.format(FORMATTER),
                "timestamp", System.currentTimeMillis()
        ));
    }
}