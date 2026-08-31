package net.xzh.iam.auth.common;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 内部供给 API 全局异常处理.
 * <p>
 * 仅作用于 controller.api 包下的身份供给接口, 将业务校验异常 (IllegalArgumentException)
 * 转换为 {@link Result} 返回 (HTTP 200 + 业务码), 使调用方 (iam-identity-service) 能拿到可读的 msg,
 * 而不是裸 500 / Internal Server Error。
 * </p>
 */
@Slf4j
@RestControllerAdvice(basePackages = "net.xzh.iam.auth.controller.api")
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public Result<Void> handleIllegalArgument(IllegalArgumentException e) {
        return Result.fail(400, e.getMessage() != null ? e.getMessage() : "参数不合法");
    }

    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("[admin-api] 未预期异常", e);
        return Result.fail(500, "服务器内部错误");
    }
}
