package net.xzh.authserver.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final SysUserMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AuthSessionService authSessionService;
    private final TenantService tenantService;

    public List<SysUser> list() {
        List<SysUser> users = mapper.selectList(new QueryWrapper<SysUser>().orderByAsc("id"));
        for (SysUser user : users) {
            user.setTenantIds(tenantService.listTenantsOfUser(user.getId()).stream().map(t -> t.getId()).toList());
        }
        return users;
    }

    public SysUser get(Long id) {
        SysUser user = mapper.selectById(id);
        if (user != null) {
            user.setTenantIds(tenantService.listTenantsOfUser(id).stream().map(t -> t.getId()).toList());
        }
        return user;
    }

    public SysUser getByUsername(String username) {
        return mapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("username", username));
    }

    @Transactional
    public void create(SysUser user) {
        if (getByUsername(user.getUsername()) != null) {
            throw new IllegalArgumentException("用户名已存在: " + user.getUsername());
        }
        if (!user.getPassword().startsWith("$")) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        if (user.getEnabled() == null) user.setEnabled(true);
        // 业务标签 (仅展示/审计, 不参与准入判定): admin=管理端, client=客户端, 默认客户端
        if (user.getUserLabel() == null || user.getUserLabel().isBlank()) user.setUserLabel("client");
        if (!Set.of("admin", "client", "wechat").contains(user.getUserLabel())) {
            throw new IllegalArgumentException("业务标签不合法, 仅支持 admin=管理端, client=客户端, wechat=微信端: " + user.getUserLabel());
        }
        if (user.getAccountNonExpired() == null) user.setAccountNonExpired(true);
        if (user.getAccountNonLocked() == null) user.setAccountNonLocked(true);
        if (user.getCredentialsNonExpired() == null) user.setCredentialsNonExpired(true);
        // 生成业务用户编码 (对外/下放引用, 内部主键不下放)
        if (user.getUserCode() == null || user.getUserCode().isBlank()) {
            user.setUserCode(generateUserCode());
        }
        user.setCreateTime(LocalDateTime.now());
        user.setUpdateTime(LocalDateTime.now());
        mapper.insert(user);
        // 租户成员关系
        tenantService.assignTenantsToUser(user.getId(), user.getTenantIds());
        log.info("新增用户 username={}, userCode={}", user.getUsername(), user.getUserCode());
    }

    /** 业务用户编码: u_ + 32 位随机十六进制 */
    private String generateUserCode() {
        return "u_" + UUID.randomUUID().toString().replace("-", "");
    }

    @Transactional
    public void update(Long id, SysUser user) {
        SysUser existing = mapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("用户不存在: " + id);

        boolean passwordChanged = false;
        if (user.getNickname() != null) existing.setNickname(user.getNickname());
        if (user.getEmail() != null) existing.setEmail(user.getEmail());
        if (user.getPhone() != null) existing.setPhone(user.getPhone());
        if (user.getAvatar() != null) existing.setAvatar(user.getAvatar());
        if (user.getUserLabel() != null && !user.getUserLabel().isBlank()) {
            if (!Set.of("admin", "client", "wechat").contains(user.getUserLabel())) {
                throw new IllegalArgumentException("业务标签不合法, 仅支持 admin=管理端, client=客户端, wechat=微信端");
            }
            existing.setUserLabel(user.getUserLabel());
        }
        if (user.getEnabled() != null) existing.setEnabled(user.getEnabled());
        // 处理密码: 编辑时若填了新密码则加密更新, 留空则不修改
        if (StringUtils.hasText(user.getPassword()) && !user.getPassword().startsWith("$")) {
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
    public void resetPassword(Long id) {
        SysUser user = mapper.selectById(id);
        if (user == null) throw new IllegalArgumentException("用户不存在: " + id);
        String newPassword = UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdateTime(LocalDateTime.now());
        mapper.updateById(user);

        // TODO: 接入短信网关, 将新密码通过短信发送给用户手机 (user.getPhone())
        //       短信发送失败不应影响密码重置流程, 建议异步发送 + 失败重试
        // 临时: 通过 log 输出新密码, 仅供开发测试阶段使用, 上线前必须移除
        log.info("重置密码 username={}, newPassword={}", user.getUsername(), newPassword);

        // 重置密码后强制下线 (事务外执行, 避免 Redis 异常导致密码更新回滚)
        kickOfflineSafely(user.getUserCode(), user.getUsername());
    }

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
}
