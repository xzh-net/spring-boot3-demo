package net.xzh.iam.open.common;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.common.Result;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 开放平台管理/开放接口全局异常处理.
 * <p>
 * 将业务校验异常 (IllegalArgumentException) 转换为 {@link Result} 返回
 * (HTTP 200 + 业务码), 使调用方能拿到可读的 msg。
 */
@Slf4j
@RestControllerAdvice(basePackages = "net.xzh.iam.open.controller")
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public Result<Void> handleIllegalArgument(IllegalArgumentException e) {
        return Result.fail(400, e.getMessage() != null ? e.getMessage() : "参数不合法");
    }

    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("[open-api] 未预期异常", e);
        return Result.fail(500, "服务器内部错误");
    }
}
