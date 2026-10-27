package net.xzh.iam.auth.security.userdetails;

import java.util.List;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.SysUser;
import net.xzh.iam.auth.mapper.SysUserMapper;
import net.xzh.iam.resource.service.PermissionService;

/**
 * OAuth2 授权登录 / 设备验证 / 密码模式的统一 {@link UserDetailsService} 实现（全量 IdP 自持用户源）。
 * <p>
 * 单库合并版：用户凭据收归 {@code iam.sys_user}（本地库查询 + BCrypt 校验，登录零远程调用）。
 * principal name 采用业务用户编码 {@code user_code}（即令牌 sub），业务 RBAC 角色由同库
 * {@link PermissionService#findRoleCodes} 按 user_code 供给 (角色编码原样, 不拼 ROLE_ 前缀);
 * 本地角色查询异常时降级为空角色 (fail-closed, 粗档令牌与 user_label 降级猜测均已退役)。
 * 签发准入由签发准入过滤器按 scope∧RBAC 交集 fail-closed 把关 (旧 iam_client_policy 已退役),
 * 令牌业务码由自省层双维交集承担。
 * <p>
 * 命名说明: 历史上曾按「门户 / 管理端」双服务各配一个 UserDetailsService, 单库合并后只剩本类
 * 一个统一 IdP (服务 admin-app / portal-app / web-app / device-app / mobile-app 全部客户端),
 * 故由 PortalUserDetailsService 更名 PlatformUserDetailsService, 避免与 portal-app / portal 域 /
 * PORTAL 角色 / portal.profile scope 等无关的 portal 概念混淆。
 *
 * @see UserDetailsService
 */
@Slf4j
@Component("platformUserDetailsService")
public final class PlatformUserDetailsService implements UserDetailsService {

    /** 基于 MyBatis-Plus 的用户数据访问接口，用于按用户名查询用户（iam.sys_user）。 */
    private final SysUserMapper sysUserMapper;

    /** 同库 RBAC 角色供给 (sys_user_role → sys_role)。 */
    private final PermissionService permissionService;

    public PlatformUserDetailsService(SysUserMapper sysUserMapper, PermissionService permissionService) {
        this.sysUserMapper = sysUserMapper;
        this.permissionService = permissionService;
    }

    /**
     * 按用户名加载用户详情（本地库 iam.sys_user）。
     * <ol>
     *   <li>校验用户名非空，为空时直接抛出 {@link UsernameNotFoundException}；</li>
     *   <li>按用户名精确查询，未命中时抛出 {@link UsernameNotFoundException}；</li>
     *   <li>以业务用户编码 user_code 作为 principal name（令牌 sub），业务 RBAC 角色经
     *       {@link PermissionService#findRoleCodes} 按 user_code 同库获取（角色编码原样返回）；</li>
     *   <li>角色查询异常时降级为空角色（fail-closed，粗档令牌与 user_label 降级猜测均已退役）；</li>
     *   <li>构建并返回 Spring Security 的 {@link UserDetails} 实体，包含启用状态、账户过期、凭证过期、锁定等完整属性。</li>
     * </ol>
     *
     * @param username 登录用户名
     * @return 已填充用户信息的 {@link UserDetails} 实例 (principal name = user_code)
     * @throws UsernameNotFoundException 用户名空或用户不存在时抛出
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!StringUtils.hasText(username)) {
            throw new UsernameNotFoundException("用户名不能为空");
        }

        SysUser user = sysUserMapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("username", username)
        );

        if (user == null) {
            log.warn("账号不存在: {}", username);
            throw new UsernameNotFoundException("账号不存在: " + username);
        }

        return buildUserDetails(user);
    }

    /**
     * 按业务用户编码 (令牌 sub / principal name) 加载用户详情。
     * 设备验证链路在 token 签发阶段 principal name 已是 user_code, 需按 user_code 反查。
     *
     * @param userCode 业务用户编码
     * @return 已填充用户信息的 {@link UserDetails} 实例 (principal name = user_code)
     * @throws UsernameNotFoundException 用户不存在时抛出
     */
    public UserDetails loadUserByUserCode(String userCode) throws UsernameNotFoundException {
        if (!StringUtils.hasText(userCode)) {
            throw new UsernameNotFoundException("用户编码不能为空");
        }
        SysUser user = sysUserMapper.selectOne(
                new QueryWrapper<SysUser>()
                        .eq("user_code", userCode)
        );
        if (user == null) {
            log.warn("用户编码不存在: {}", userCode);
            throw new UsernameNotFoundException("用户编码不存在: " + userCode);
        }
        return buildUserDetails(user);
    }

    private UserDetails buildUserDetails(SysUser user) {
        String userCode = user.getUserCode();

        // 业务 RBAC 角色: 同库 sys_user_role 按 user_code 供给 (角色编码原样, 不拼 ROLE_ 前缀)。
        // 粗档 ADMIN_SERVICE_TOKEN 与 user_label 降级猜测均已退役: 角色查询异常时降级为空角色
        // (fail-closed, 无 user_label 依赖), 令牌业务码由自省层双维交集与签发准入共同把关。
        List<SimpleGrantedAuthority> authorities;
        try {
            Set<String> roles = Set.copyOf(permissionService.findRoleCodes(userCode));
            authorities = new java.util.ArrayList<>();
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
            log.debug("用户 {} (user_code={}) RBAC 角色: {}", user.getUsername(), userCode, roles);
        } catch (Exception e) {
            authorities = new java.util.ArrayList<>();
            log.warn("RBAC 角色解析失败 userCode={}, 降级空角色 (fail-closed): {}", userCode, e.getMessage());
        }

        return new User(
                userCode,
                user.getPassword(),
                Boolean.TRUE.equals(user.getEnabled()),
                Boolean.TRUE.equals(user.getAccountNonExpired()),
                Boolean.TRUE.equals(user.getCredentialsNonExpired()),
                Boolean.TRUE.equals(user.getAccountNonLocked()),
                authorities
        );
    }
}
