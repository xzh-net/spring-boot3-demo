package net.xzh.iam.auth.security.lockout;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 登录防爆破服务 (A-P1-2): Redis 失败计数 + 临时锁定.
 * <p>
 * 双维度计数, <b>任一命中即锁</b>:
 * <ul>
 *   <li><b>用户名维度</b>: 防定向撞库 —— 单账号窗口内失败达阈值即锁该账号;</li>
 *   <li><b>IP 维度</b>: 防密码喷洒 —— 单 IP 跨多账号失败达阈值即锁该 IP
 *       (阈值高于账号维度, 兼顾共享出口/NAT 场景).</li>
 * </ul>
 * 锁定为 <b>Redis TTL 自然解锁</b> (无需管理员干预, 锁定机制不被反向利用为 DoS);
 * 管理员人工升级通道 = 用户管理页禁用账号 (enabled=0), 二者正交。
 * 触发锁定时清零对应计数, 解锁后重新计数 (防「解锁瞬间旧计数再次触发」抖动)。
 * 成功登录仅清用户名计数, IP 计数保留至窗口过期 —— 否则攻击者持一个合法账号即可重置喷洒计数。
 * </p>
 *
 * <p>Key 设计 (均带 TTL):</p>
 * <pre>
 * login:fail:user:{username}  计数, TTL=窗口
 * login:fail:ip:{ip}          计数, TTL=窗口
 * login:lock:user:{username}  锁标, TTL=锁定时长
 * login:lock:ip:{ip}          锁标, TTL=锁定时长
 * </pre>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginGuardService {

    private static final String KEY_FAIL_USER = "login:fail:user:";
    private static final String KEY_FAIL_IP = "login:fail:ip:";
    private static final String KEY_LOCK_USER = "login:lock:user:";
    private static final String KEY_LOCK_IP = "login:lock:ip:";

    private final StringRedisTemplate redisTemplate;

    /** 失败计数窗口 (秒): 窗口内计数未达阈值则自然过期归零 */
    @Value("${iam.login-guard.window-seconds:600}")
    private long windowSeconds;

    /** 锁定时长 (秒): 到期 Redis TTL 自动解锁 */
    @Value("${iam.login-guard.lock-seconds:900}")
    private long lockSeconds;

    /** 单用户名窗口内失败阈值 */
    @Value("${iam.login-guard.user-threshold:5}")
    private long userThreshold;

    /** 单 IP 窗口内失败阈值 (防喷洒, 高于账号阈值以容忍共享出口) */
    @Value("${iam.login-guard.ip-threshold:20}")
    private long ipThreshold;

    /**
     * 认证前锁定检查 —— 命中则抛 LockedException (含正确密码也拒绝, A-P1-2 核心语义)。
     *
     * @param username 归一化用户名 (小写)
     * @param ip       客户端 IP
     */
    public void assertNotLocked(String username, String ip) {
        boolean userLocked = Boolean.TRUE.equals(redisTemplate.hasKey(KEY_LOCK_USER + username));
        boolean ipLocked = Boolean.TRUE.equals(redisTemplate.hasKey(KEY_LOCK_IP + ip));
        if (userLocked || ipLocked) {
            log.warn("[LoginGuard] 锁定期内拒绝登录: user={}, ip={}, 命中维度={}",
                    username, ip, userLocked && ipLocked ? "user+ip" : (userLocked ? "user" : "ip"));
            throw new LockedException("登录尝试过多, 请稍后再试");
        }
    }

    /**
     * 认证失败计数: 双维度 INCR (首见设窗口 TTL), 达阈值即置锁并清零该维度计数。
     *
     * @return true = 本次失败触发了新锁定 (调用方可转抛 LockedException 让用户立即获知)
     */
    public boolean recordFailure(String username, String ip) {
        long userFail = incrWithWindow(KEY_FAIL_USER + username);
        long ipFail = incrWithWindow(KEY_FAIL_IP + ip);

        boolean userLock = userFail >= userThreshold;
        boolean ipLock = ipFail >= ipThreshold;
        if (userLock) {
            lock(KEY_LOCK_USER + username, KEY_FAIL_USER + username);
            log.warn("[LoginGuard] 触发账号锁定: user={}, 窗口内失败 {} 次 >= {}, 锁定 {} 秒",
                    username, userFail, userThreshold, lockSeconds);
        }
        if (ipLock) {
            lock(KEY_LOCK_IP + ip, KEY_FAIL_IP + ip);
            log.warn("[LoginGuard] 触发 IP 锁定: ip={}, 窗口内失败 {} 次 >= {}, 锁定 {} 秒",
                    ip, ipFail, ipThreshold, lockSeconds);
        }
        if (!userLock && !ipLock) {
            log.warn("[LoginGuard] 登录失败: user={}, ip={}, 账号计数 {}/{}, IP 计数 {}/{}",
                    username, ip, userFail, userThreshold, ipFail, ipThreshold);
        }
        return userLock || ipLock;
    }

    /**
     * 认证成功: 仅清用户名计数 (IP 计数保留至窗口过期, 防合法账号重置喷洒计数)。
     */
    public void recordSuccess(String username, String ip) {
        redisTemplate.delete(KEY_FAIL_USER + username);
        log.info("[LoginGuard] 登录成功: user={}, ip={}", username, ip);
    }

    /** 锁定时长 (分钟), 用于失败跳转 URL 携带, 登录页展示具体等待时间 */
    public long lockMinutes() {
        return Math.max(1, (lockSeconds + 59) / 60);
    }

    // ------------------------------------------------------------------

    private long incrWithWindow(String key) {
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            // 首次计数设窗口 TTL; 后续 INCR 不重置窗口 (固定窗口语义)
            redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
        }
        return count != null ? count : 0L;
    }

    /** 置锁 (TTL 自动解锁) + 清零对应计数 (防解锁瞬间旧计数二次触发) */
    private void lock(String lockKey, String failKey) {
        redisTemplate.opsForValue().set(lockKey, "1", lockSeconds, TimeUnit.SECONDS);
        redisTemplate.delete(failKey);
    }

    /** 用户名归一化: 与 DB 校验语义一致 (MySQL utf8mb4 默认排序规则大小写不敏感) */
    public static String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase();
    }
}
