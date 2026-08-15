package net.xzh.authserver.security.userdetails;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.SysUser;
import net.xzh.authserver.mapper.SysUserMapper;
import net.xzh.authserver.remote.RemoteRoleService;

/**
 * OAuth2 授权登录 / 设备验证 / 密码模式的统一 {@link UserDetailsService} 实现（全量 IdP 自持用户源）。
 * <p>
 * V6.2 定版：用户凭据收归 {@code iam_identity.sys_user}（本地库查询 + BCrypt 校验，登录零远程凭据调用）。
 * principal name 采用业务用户编码 {@code user_code}（即令牌 sub），业务 RBAC 角色由资源中心
 * {@link RemoteRoleService} (D6) 按 user_code 供给，替换历史 user_label 的粗粒度映射；
 * 资源中心不可达时降级按 user_label 映射（ROLE_ADMIN/ROLE_USER），保证管理端在 RBAC 服务中断时仍可登录
 * （令牌签发准入仍在 {@code ClientUserPolicyService} 按 fail-closed 把关）。
 * <p>
 * 历史命名 PortalUserDetailsService (bean: portalUserDetailsService) 保留不变。
 *
 * @see UserDetailsService
 */
@Slf4j
@Component("portalUserDetailsService")
public final class PortalUserDetailsService implements UserDetailsService {

    /** 基于 MyBatis-Plus 的用户数据访问接口，用于按用户名查询用户（iam_identity.sys_user）。 */
    private final SysUserMapper sysUserMapper;

    /** 资源中心 RBAC 角色供给 (D6)。 */
    private final RemoteRoleService remoteRoleService;

    public PortalUserDetailsService(SysUserMapper sysUserMapper, RemoteRoleService remoteRoleService) {
        this.sysUserMapper = sysUserMapper;
        this.remoteRoleService = remoteRoleService;
    }

    /**
     * 根据用户名加载用户详情（本地库 iam_identity.sys_user）。
     * <ol>
     *   <li>校验用户名非空，为空时直接抛出 {@link UsernameNotFoundException}；</li>
     *   <li>按用户名精确查询，未命中时抛出 {@link UsernameNotFoundException}；</li>
     *   <li>以业务用户编码 user_code 作为 principal name（令牌 sub），业务 RBAC 角色经
     *       {@link RemoteRoleService} 按 user_code 获取（角色权威在资源中心）；</li>
     *   <li>资源中心不可达时降级按 user_label 映射 ROLE_ADMIN/ROLE_USER，避免管理端被锁死；</li>
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

        // 业务 RBAC 角色: 资源中心 D6 按 user_code 供给; 不可达时降级按 user_label 粗粒度映射
        List<SimpleGrantedAuthority> authorities;
        try {
            Set<String> roles = remoteRoleService.getUserRoles(userCode);
            authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            log.debug("用户 {} (user_code={}) RBAC 角色: {}", user.getUsername(), userCode, roles);
        } catch (Exception e) {
            boolean admin = "admin".equals(user.getUserLabel());
            authorities = Collections.singletonList(
                    new SimpleGrantedAuthority(admin ? "ROLE_ADMIN" : "ROLE_USER"));
            log.warn("RBAC 角色解析失败 userCode={}, 降级按 user_label 映射: {}", userCode, e.getMessage());
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
