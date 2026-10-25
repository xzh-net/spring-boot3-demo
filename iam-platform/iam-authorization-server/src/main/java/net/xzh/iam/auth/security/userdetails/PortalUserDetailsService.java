package net.xzh.iam.auth.security.userdetails;

import java.util.Collections;
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
 * 本地角色查询异常时降级按 user_label 映射（ADMIN_SERVICE_TOKEN/ROLE_USER），
 * 保证管理端在异常时仍可登录
 * （签发准入：旧 ClientUserPolicyService 登录边界策略已随 iam_client_policy 退役,
 *  双维准入由自省层 scope∧RBAC 交集承担）。
 * <p>
 * 历史命名 PortalUserDetailsService (bean: portalUserDetailsService) 保留不变。
 *
 * @see UserDetailsService
 */
@Slf4j
@Component("portalUserDetailsService")
public final class PortalUserDetailsService implements UserDetailsService {

    /** 基于 MyBatis-Plus 的用户数据访问接口，用于按用户名查询用户（iam.sys_user）。 */
    private final SysUserMapper sysUserMapper;

    /** 同库 RBAC 角色供给 (sys_user_role → sys_role)。 */
    private final PermissionService permissionService;

    public PortalUserDetailsService(SysUserMapper sysUserMapper, PermissionService permissionService) {
        this.sysUserMapper = sysUserMapper;
        this.permissionService = permissionService;
    }

/** 管理端业务角色编码 (逻辑引用资源中心 sys_role.role_code) */
    private static final String ADMIN_ROLE_CODE = "ADMIN";

    /** 管理服务凭证类别标识: 用户令牌持有者具备管理端角色时发给令牌的 authority */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    /**
     * 按用户名加载用户详情（本地库 iam.sys_user）。
     * <ol>
     *   <li>校验用户名非空，为空时直接抛出 {@link UsernameNotFoundException}；</li>
     *   <li>按用户名精确查询，未命中时抛出 {@link UsernameNotFoundException}；</li>
     *   <li>以业务用户编码 user_code 作为 principal name（令牌 sub），业务 RBAC 角色经
     *       {@link PermissionService#findRoleCodes} 按 user_code 同库获取（角色编码原样返回）；
     *       业务角色含 {@code ADMIN} 时额外注入 {@code ADMIN_SERVICE_TOKEN}（管理服务凭证）作为令牌类别；</li>
     *   <li>角色查询异常时降级按 user_label 映射 ADMIN_SERVICE_TOKEN/ROLE_USER，避免管理端被锁死；</li>
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

        // 业务 RBAC 角色: 同库 sys_user_role 按 user_code 供给 (角色编码原样, 不拼 ROLE_ 前缀);
        // 令牌类别: 业务角色含管理端角色 → 注入 ADMIN_SERVICE_TOKEN (管理服务凭证)
        List<SimpleGrantedAuthority> authorities;
        try {
            Set<String> roles = Set.copyOf(permissionService.findRoleCodes(userCode));
            authorities = new java.util.ArrayList<>();
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
            }
            if (roles.contains(ADMIN_ROLE_CODE)) {
                authorities.add(new SimpleGrantedAuthority(ADMIN_SERVICE_TOKEN));
            }
            log.debug("用户 {} (user_code={}) RBAC 角色: {}", user.getUsername(), userCode, roles);
        } catch (Exception e) {
            boolean admin = "admin".equals(user.getUserLabel());
            authorities = Collections.singletonList(
                    new SimpleGrantedAuthority(admin ? ADMIN_SERVICE_TOKEN : "ROLE_USER"));
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
