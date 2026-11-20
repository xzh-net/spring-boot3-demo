package net.xzh.iam.auth.security.lockout;

import java.io.IOException;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * 登录失败处理器 (A-P1-2): 失败计数 + 「锁定/普通失败」分流跳转.
 * <p>
 * <b>计数放在此处而非认证装饰器</b>: 失败路径上本地与父级 ProviderManager 会先后
 * 调用认证器 (父级复用同一 bean, INCR 翻倍 → 第 3 次请求即达阈值 5), 而 Spring 对
 * 每个失败请求<b>恰好调用本处理器一次</b>, 与 AuthenticationManager 拓扑无关。
 * </p>
 * <ul>
 *   <li>{@link LockedException} (锁定期内, 含正确密码被拒) → lockedUrl, <b>不计数</b>
 *       (锁定期内的尝试不累计, 锁定时长不被延长);</li>
 *   <li>{@link BadCredentialsException} (密码错/用户不存在) → 计数;
 *       若本次触发锁定 → lockedUrl (用户第 5 次即获知), 否则 normalUrl;</li>
 *   <li>其他异常 (Disabled/CredentialsExpired/内部错误等, 非「猜密码」信号) →
 *       normalUrl, <b>不计数</b> —— 避免 DB 故障等导致账号被误锁。</li>
 * </ul>
 * normalUrl 与改造前默认跳转逐字节一致 (主链 /login.html?error,
 * 设备链 /login.html?type=device&error —— 已取改前基线)。
 */
@RequiredArgsConstructor
public class LockoutAwareFailureHandler implements AuthenticationFailureHandler {

    private final LoginGuardService loginGuardService;
    /** 普通失败落点 (与改造前默认行为一致) */
    private final String normalUrl;
    /** 锁定落点 (含 error=locked 标记, retry 分钟数由本处理器追加) */
    private final String lockedUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        // 锁定期内拒绝: 已计数/已锁定, 直接跳锁定提示, 不再累计
        if (exception instanceof LockedException) {
            redirectLocked(response);
            return;
        }

        // 仅「猜密码」信号计数: 密码错误 / 用户不存在 (Dao 隐藏用户不存在 → 同为 BadCredentials)
        if (exception instanceof BadCredentialsException) {
            String username = LoginGuardService.normalizeUsername(request.getParameter("username"));
            String ip = request.getRemoteAddr() != null ? request.getRemoteAddr() : "unknown";
            boolean newlyLocked = loginGuardService.recordFailure(username, ip);
            if (newlyLocked) {
                redirectLocked(response);
                return;
            }
        }

        response.sendRedirect(normalUrl);
    }

    private void redirectLocked(HttpServletResponse response) throws IOException {
        response.sendRedirect(lockedUrl + "&retry=" + loginGuardService.lockMinutes());
    }
}
