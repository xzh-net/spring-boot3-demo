package net.xzh.iam.common;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 管理/门户 API 全局异常处理 (合并原认证中心与资源中心两份 advice, 二保一防 advice 互扰).
 * <p>
 * 仅作用于两域接口: auth 管理 API (controller.admin) 与 resource 各能力域 (controller 全包),
 * 将业务校验异常 (IllegalArgumentException) 转换为 {@link Result} 返回 (HTTP 200 + 业务码),
 * 使管理前端 App.api 能拿到可读的 msg, 而不是裸 500 / Internal Server Error。
 * </p>
 */
@Slf4j
@RestControllerAdvice(basePackages = {
        "net.xzh.iam.auth.controller.admin",
        "net.xzh.iam.resource.controller"
})
public class GlobalExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public Result<Void> handleIllegalArgument(IllegalArgumentException e) {
        return Result.fail(400, e.getMessage() != null ? e.getMessage() : "参数不合法");
    }

    @ExceptionHandler(Exception.class)
    public Result<Void> handleException(Exception e) {
        log.error("[api] 未预期异常", e);
        return Result.fail(500, "服务器内部错误");
    }
}
