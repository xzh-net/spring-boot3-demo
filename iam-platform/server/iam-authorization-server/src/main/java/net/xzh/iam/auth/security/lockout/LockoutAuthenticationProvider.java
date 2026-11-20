package net.xzh.iam.auth.security.lockout;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 登录防爆破装饰器 (A-P1-2): 包装 {@code platformDaoProvider}, 两条表单登录链
 * (/login 与 /device-login) 共用, 单点覆盖全部用户名密码认证路径.
 * <p>
 * 职责顺序:
 * <ol>
 *   <li><b>认证前锁定检查</b> —— 命中 user/IP 任一锁定即拒 (正确密码也拒绝);</li>
 *   <li>委托 {@code DaoAuthenticationProvider} 校验凭据;</li>
 *   <li><b>失败</b> → 双维度计数; 若本次触发锁定 → 转抛 LockedException 让用户立即获知,
 *       否则原样抛 BadCredentials (登录页文案不变, 不泄露用户是否存在);</li>
 *   <li><b>成功</b> → 清用户名计数 + 成功日志 (登录审计第 1 层: log 级).</li>
 * </ol>
 * 仅处理 UsernamePasswordAuthenticationToken —— 设备码/客户端认证等其他 token 类型
 * 直接透传委托方, 不受影响。
 */
@Slf4j
@RequiredArgsConstructor
public class LockoutAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationProvider delegate;
    private final LoginGuardService loginGuardService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof UsernamePasswordAuthenticationToken)) {
            return delegate.authenticate(authentication);
        }

        String username = LoginGuardService.normalizeUsername(authentication.getName());
        String ip = resolveIp(authentication);

        // 1. 认证前锁定检查 (含正确密码一律拒绝)
        //    只读操作, 被调用多次也无副作用 —— 失败计数不放这里:
        //    失败时本地与父级 ProviderManager 会先后调用本装饰器 (INCR 会翻倍),
        //    计数统一由 LockoutAwareFailureHandler 执行 (每失败请求恰一次)。
        loginGuardService.assertNotLocked(username, ip);

        // 2. 委托真实凭据校验 (DaoAuthenticationProvider)
        Authentication result = delegate.authenticate(authentication);
        // 3. 成功 → 清计数 + 审计日志 (成功路径本地命中即返回, 不回落父级, 恰一次)
        loginGuardService.recordSuccess(username, ip);
        return result;
        // 失败异常原样透传: 计数与「是否刚触发锁定」的判定在失败处理器中完成
        // (DisabledException / LockedException(账号字段) 等非猜密码类异常由处理器识别, 不计数)
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return delegate.supports(authentication);
    }

    /** 从 Authentication.details 取客户端 IP (表单过滤器已注入 WebAuthenticationDetails) */
    private String resolveIp(Authentication authentication) {
        if (authentication.getDetails() instanceof WebAuthenticationDetails details
                && details.getRemoteAddress() != null) {
            return details.getRemoteAddress();
        }
        return "unknown";
    }
}
