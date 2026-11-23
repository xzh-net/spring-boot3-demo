package net.xzh.iam.auth.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.SysUser;
import net.xzh.iam.auth.mapper.SysUserMapper;
import net.xzh.iam.resource.service.ApplicationService;
import net.xzh.iam.resource.service.RbacService;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final SysUserMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthSessionService authSessionService;
    private final RbacService rbacService;
    private final ApplicationService applicationService;

    public List<SysUser> list() {
        return mapper.selectList(new QueryWrapper<SysUser>().orderByAsc("id"));
    }

    public SysUser get(Long id) {
        return mapper.selectById(id);
    }

    public SysUser getByUsername(String username) {
        return mapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("username", username));
    }

    /** 标准 UUID 编码格式 (如 550e8400-e29b-41d4-a716-446655440000) */
    private static final java.util.regex.Pattern UUID_FORMAT = java.util.regex.Pattern
            .compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    @Transactional
    public void create(SysUser user) {
        if (getByUsername(user.getUsername()) != null) {
            throw new IllegalArgumentException("用户名已存在: " + user.getUsername());
        }
        if (!user.getPassword().startsWith("$")) {
            validatePasswordStrength(user.getPassword()); // A-P2-5: 明文设密统一强度校验
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        if (user.getEnabled() == null) user.setEnabled(true);
        if (user.getAccountNonExpired() == null) user.setAccountNonExpired(true);
        if (user.getAccountNonLocked() == null) user.setAccountNonLocked(true);
        if (user.getCredentialsNonExpired() == null) user.setCredentialsNonExpired(true);
        // 生成业务用户编码 (对外/下放引用, 内部主键不下放)
        if (user.getUserCode() == null || user.getUserCode().isBlank()) {
            // 未填写则自动生成
            user.setUserCode(generateUserCode());
        } else {
            // 已填写则校验合法性, 避免与现有用户冲突 (sys_user.user_code 唯一索引)
            String code = user.getUserCode().trim();
            if (code.length() > 64) {
                throw new IllegalArgumentException("用户编码过长 (最多 64 字符)");
            }
            if (!UUID_FORMAT.matcher(code).matches()) {
                throw new IllegalArgumentException("编码格式不正确, 应为标准 UUID (如 550e8400-e29b-41d4-a716-446655440000)");
            }
            if (mapper.selectCount(new QueryWrapper<SysUser>().eq("user_code", code)) > 0) {
                throw new IllegalArgumentException("用户编码已存在: " + code);
            }
            user.setUserCode(code);
        }
        user.setCreateTime(LocalDateTime.now());
        user.setUpdateTime(LocalDateTime.now());
        mapper.insert(user);
        log.info("新增用户 username={}, userCode={}", user.getUsername(), user.getUserCode());
    }

    /** 业务用户编码: 标准 UUID 格式 (如 550e8400-e29b-41d4-a716-446655440000) */
    private String generateUserCode() {
        return UUID.randomUUID().toString();
    }

    @Transactional
    public void update(Long id, SysUser user) {
        SysUser existing = mapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("用户不存在: " + id);

        boolean passwordChanged = false;
        // 编码不可变: 有意不读取 user.getUserCode(), 编辑请求携带的 userCode 一律忽略
        if (user.getNickname() != null) existing.setNickname(user.getNickname());
        if (user.getEmail() != null) existing.setEmail(user.getEmail());
        if (user.getPhone() != null) existing.setPhone(user.getPhone());
        if (user.getAvatar() != null) existing.setAvatar(user.getAvatar());
        if (user.getEnabled() != null) existing.setEnabled(user.getEnabled());
        // 处理密码: 编辑时若填了新密码则加密更新, 留空则不修改
        if (StringUtils.hasText(user.getPassword()) && !user.getPassword().startsWith("$")) {
            validatePasswordStrength(user.getPassword()); // A-P2-5: 明文改密统一强度校验
            existing.setPassword(passwordEncoder.encode(user.getPassword()));
            passwordChanged = true;
        }
        existing.setUpdateTime(LocalDateTime.now());
        mapper.updateById(existing);
        log.info("更新用户 id={}, passwordChanged={}", id, passwordChanged);

        // 修改密码后强制下线 (放在事务外执行, 避免 Redis 异常导致回滚)
        if (passwordChanged) {
            kickOfflineSafely(existing.getUserCode(), existing.getUsername());
        }
    }

    @Transactional
    public void delete(Long id) {
        SysUser user = mapper.selectById(id);
        if (user == null) throw new IllegalArgumentException("用户不存在: " + id);

        mapper.deleteById(id);
        log.info("删除用户 id={}", id);

        // 先强制下线所有会话 (事务外执行, 避免 Redis 异常导致删除回滚)
        kickOfflineSafely(user.getUserCode(), user.getUsername());
        // 关联清理: 同库角色绑定 + USER 主体应用授权 (user_code), 失败不影响本地删除
        cleanupRelatedDataSafely(user.getUserCode());
    }

    @Transactional
    public void enable(Long id, boolean enabled) {
        SysUser user = mapper.selectById(id);
        if (user == null) throw new IllegalArgumentException("用户不存在: " + id);
        user.setEnabled(enabled);
        user.setUpdateTime(LocalDateTime.now());
        mapper.updateById(user);
        if (!enabled) {
            log.info("禁用用户, 强制下线 username={}", user.getUsername());
            kickOfflineSafely(user.getUserCode(), user.getUsername());
        }
    }

    @Transactional
    public String resetPassword(Long id) {
        SysUser user = mapper.selectById(id);
        if (user == null) throw new IllegalArgumentException("用户不存在: " + id);
        // A-P2-5: 16 位 hex (64bit 熵, 原 8 位 32bit 偏弱); 明文只经 API 返回给管理员页面
        // 一次性展示, 不再写入日志 (原明文入日志 = 读日志即得用户密码的泄露面)
        String newPassword = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdateTime(LocalDateTime.now());
        mapper.updateById(user);

        // TODO: 接入短信网关后改为异步下发 (user.getPhone()), 不再经 API 返回
        log.info("[ResetPw] 重置密码 (新密码经 API 返回, 不落日志): username={}", user.getUsername());

        // 重置密码后强制下线 (事务外执行, 避免 Redis 异常导致密码更新回滚)
        kickOfflineSafely(user.getUserCode(), user.getUsername());
        return newPassword;
    }

    /**
     * 密码强度校验 (A-P2-5): 长度 ≥8 + 含字母和数字 + 拒绝常见弱密码。
     * 挂 create/update 的明文设密路径 (预编码哈希传入不校验, 与既有 $ 前缀旁路语义一致)。
     * 抛 IllegalArgumentException → GlobalExceptionHandler 转业务 400。
     */
    private void validatePasswordStrength(String raw) {
        if (raw == null || raw.length() < 8) {
            throw new IllegalArgumentException("密码强度不足: 长度至少 8 位");
        }
        if (!raw.matches(".*[A-Za-z].*") || !raw.matches(".*\\d.*")) {
            throw new IllegalArgumentException("密码强度不足: 须同时包含字母和数字");
        }
        if (WEAK_PASSWORDS.contains(raw.toLowerCase())) {
            throw new IllegalArgumentException("密码强度不足: 该密码过于常见");
        }
    }

    /** 常见弱密码黑名单 (A-P2-5, 字典头部小表, 全小写比对) */
    private static final java.util.Set<String> WEAK_PASSWORDS = java.util.Set.of(
            "123456", "12345678", "123456789", "password", "password1", "admin",
            "administrator", "qwerty", "qwerty123", "abc123", "111111", "000000",
            "654321", "iloveyou", "letmein", "abcd1234");

    /**
     * 安全强制下线: 捕获 Redis 异常, 不影响数据库事务。
     * (Kick offline safely: catch Redis exceptions so they don't roll back DB transactions)
     */
    private void kickOfflineSafely(String userCode, String username) {
        try {
            int kicked = authSessionService.revokeUserAll(userCode);
            log.info("强制下线 username={} (userCode={}), 会话数={}", username, userCode, kicked);
        } catch (Exception e) {
            log.warn("强制下线失败 (Redis), username={}, error={}", username, e.getMessage());
        }
    }

    /**
     * 同库关联清理 (角色绑定 + USER 主体应用授权):
     * 捕获异常, 不影响本地用户删除事务 (best-effort, 失败仅打日志)。
     */
    private void cleanupRelatedDataSafely(String userCode) {
        try {
            rbacService.deleteUserRoleBindings(userCode);
            applicationService.deleteUserAuthorizations(userCode);
        } catch (Exception e) {
            log.warn("清理用户关联数据失败 (不影响本地删除), userCode={}, error={}",
                    userCode, e.getMessage());
        }
    }
}
