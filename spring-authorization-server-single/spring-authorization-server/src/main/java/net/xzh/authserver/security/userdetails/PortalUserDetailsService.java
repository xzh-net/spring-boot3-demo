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
 * 门户端 {@link UserDetailsService} 实现。
 * <p>
 * 该服务专为门户（portal）/ 设备（device）认证链路设计，与管理后台的用户详情服务分离：
 * <ul>
 *   <li>通过 SQL 条件 {@code role != 'ROLE_ADMIN'} 过滤，排除所有管理员账号，仅允许普通门户用户登录；</li>
 *   <li>被 Spring Authorization Server 的门户登录流程和设备码流程引用，用于加载用户实体并构建 authorities；</li>
 *   <li>加载的真实权限信息会被写入 OIDC {@code id_token} 的 claims 中，供下游业务系统识别用户角色。</li>
 * </ul>
 *
 * @see UserDetailsService
 */
@Slf4j
@Component("portalUserDetailsService")
public final class PortalUserDetailsService implements UserDetailsService {

    /** 基于 MyBatis-Plus 的用户数据访问接口，用于按用户名查询门户用户。 */
    private final SysUserMapper sysUserMapper;

    public PortalUserDetailsService(SysUserMapper sysUserMapper) {
        this.sysUserMapper = sysUserMapper;
    }

    /**
     * 根据用户名加载门户用户详情。
     * <p>
     * 与管理后台的用户查询逻辑不同，本方法包含门户特有的过滤规则：
     * <ol>
     *   <li>校验用户名非空，为空时直接抛出 {@link UsernameNotFoundException}；</li>
     *   <li>使用 {@link QueryWrapper} 构建查询条件，精确匹配用户名并排除 {@code ROLE_ADMIN} 角色，
     *       确保管理员账号无法通过门户链路登录；</li>
     *   <li>若查询结果为 {@code null}，说明用户不存在或属于被排除的管理员角色，记录警告日志后抛出异常；</li>
     *   <li>将用户角色封装为 {@link SimpleGrantedAuthority} 列表（单元素），
     *       若角色为空则默认授予 {@code ROLE_USER}；</li>
     *   <li>构建并返回 Spring Security 的 {@link UserDetails} 实体，包含启用状态、账户过期、凭证过期、锁定等完整属性。</li>
     * </ol>
     *
     * @param username 门户用户的登录用户名
     * @return 已填充门户用户信息的 {@link UserDetails} 实例
     * @throws UsernameNotFoundException 用户名空、用户不存在或为管理员角色时抛出
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!StringUtils.hasText(username)) {
            throw new UsernameNotFoundException("用户名不能为空");
        }

        SysUser user = sysUserMapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("username", username)
                        .ne("role", "ROLE_ADMIN")
        );

        if (user == null) {
            log.warn("门户用户账号不存在或无权限: {}", username);
            throw new UsernameNotFoundException("账号不存在或无权限: " + username);
        }

        String role = user.getRole() != null ? user.getRole() : "ROLE_USER";
        List<SimpleGrantedAuthority> authorities =
                Collections.singletonList(new SimpleGrantedAuthority(role));

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