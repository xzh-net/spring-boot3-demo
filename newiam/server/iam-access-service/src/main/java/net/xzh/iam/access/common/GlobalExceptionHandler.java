package net.xzh.iam.access.common;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 管理/门户 API 全局异常处理.
 * <p>
 * 仅作用于 controller 包下的各能力域接口 (admin / portal / internal / client),
 * 将业务校验异常 (IllegalArgumentException) 转换为 {@link Result} 返回 (HTTP 200 + 业务码),
 * 使管理前端 App.api 能拿到可读的 msg, 而不是裸 500 / Internal Server Error。
 * 与认证中心 net.xzh.authserver.common.GlobalExceptionHandler 行为对齐。
 * </p>
 */
@Slf4j
@RestControllerAdvice(basePackages = "net.xzh.iam.access.controller")
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public Result<Void> handleIllegalArgument(IllegalArgumentException e) {
        return Result.fail(400, e.getMessage() != null ? e.getMessage() : "参数不合法");
    }

    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("[resource-api] 未预期异常", e);
        return Result.fail(500, "服务器内部错误");
    }
}