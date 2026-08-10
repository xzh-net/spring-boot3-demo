package net.xzh.authserver.security.userdetails;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;

/**
 * 管理员 {@link UserDetailsService} 实现。
 * <p>
 * 该服务专门用于管理员身份认证，加载用户时会额外过滤 {@code role=ROLE_ADMIN}，
 * 只有具备管理员角色的用户才能通过此服务完成登录。
 * 被 Spring Security 登录过滤器链中的管理员认证链路引用（Order(3)）。
 */
@Slf4j
@Component("adminUserDetailsService")
public final class AdminUserDetailsService implements UserDetailsService {

    /** 系统用户数据访问接口，用于根据用户名和管理员角色查询用户。 */
    private final SysUserMapper sysUserMapper;

    public AdminUserDetailsService(SysUserMapper sysUserMapper) {
        this.sysUserMapper = sysUserMapper;
    }

    /**
     * 根据用户名加载管理员用户信息。
     * <p>
     * 与普通用户加载逻辑不同，此方法在查询时会附加 {@code role=ROLE_ADMIN} 条件，
     * 仅允许具备管理员角色的用户通过认证。
     * 若用户名为空、用户不存在或用户不具有管理员角色，均会抛出 {@link UsernameNotFoundException}。
     *
     * @param username 用户名，不能为空
     * @return 符合管理员条件的 {@link UserDetails} 实例
     * @throws UsernameNotFoundException 当用户名为空、用户不存在或非管理员账号时抛出
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!StringUtils.hasText(username)) {
            throw new UsernameNotFoundException("用户名不能为空");
        }

        SysUser user = sysUserMapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("username", username)
                        .eq("role", "ROLE_ADMIN")
        );

        if (user == null) {
            log.warn("管理员账号不存在或无权限: {}", username);
            throw new UsernameNotFoundException("账号不存在或非管理员账号: " + username);
        }

        List<SimpleGrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));

        return new User(
                user.getUsername(),
                user.getPassword(),
                Boolean.TRUE.equals(user.getEnabled()),
                Boolean.TRUE.equals(user.getAccountNonExpired()),
                Boolean.TRUE.equals(user.getCredentialsNonExpired()),
                Boolean.TRUE.equals(user.getAccountNonLocked()),
                authorities
        );
    }
}