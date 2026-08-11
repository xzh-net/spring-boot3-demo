package net.xzh.authserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 用户密码初始化器.
 * <p>
 * 确保用户密码被正确编码，修复因密码编码问题导致的登录失败。
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserPasswordInitializer implements ApplicationRunner {

    private final SysUserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_PASSWORD = "123456";

    @Override
    public void run(ApplicationArguments args) {
        ensureUserPassword("user", DEFAULT_PASSWORD);
        ensureUserPassword("admin", DEFAULT_PASSWORD);
    }

    private void ensureUserPassword(String username, String rawPassword) {
        try {
            SysUser user = userMapper.selectByUsername(username);
            if (user == null) {
                log.warn("[UserPasswordInit] 用户 {} 不存在, 跳过", username);
                return;
            }

            // 验证密码是否正确
            if (passwordEncoder.matches(rawPassword, user.getPassword())) {
                log.info("[UserPasswordInit] 用户 {} 密码正确, 跳过", username);
                return;
            }

            // 密码不正确，更新为新的正确密码
            String newHash = passwordEncoder.encode(rawPassword);
            user.setPassword(newHash);
            userMapper.updateById(user);
            log.info("[UserPasswordInit] 用户 {} 密码已重置为默认密码", username);
        } catch (Exception e) {
            log.error("[UserPasswordInit] 处理用户 {} 密码失败", username, e);
        }
    }
}
