package net.xzh.iam.auth.security.userdetails;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.SysUser;
import net.xzh.iam.auth.mapper.SysUserMapper;
import net.xzh.iam.auth.remote.AccessDecisionClient;

/**
 * OAuth2 授权登录 / 设备验证 / 密码模式的统一 {@link UserDetailsService} 实现（全量 IdP 自持用户源）。
 * <p>
 * 用户凭据收归 {@code iam_identity_v2.sys_user}（本地库查询 + BCrypt 校验，登录零远程凭据调用）。
 * principal name 采用业务用户编码 {@code user_code}（即令牌 sub）。
 * <p>
 * <b>干净切割后的角色供给</b>: 业务角色不再本地拉取评估, 统一经
 * {@link AccessDecisionClient} 向权限中心 decide 接口问询（SWR 缓存, 30s 新鲜窗口 +
 * max-stale 沿用最后真实判定）。权限中心不可达且缓存耗尽时抛出
 * {@link InternalAuthenticationServiceException} <b>fail-closed 拒绝登录</b>——
 * 旧版按 user_label 展示字段猜测角色的降级 hack 已彻底移除, 无任何猜测成分。
 * <p>
 * 历史命名 PortalUserDetailsService (bean: portalUserDetailsService) 保留不变。
 *
 * @see UserDetailsService
 */
@Slf4j
@Component("portalUserDetailsService")
public final class PortalUserDetailsService implements UserDetailsService {

    /** 基于 MyBatis-Plus 的用户数据访问接口，用于按用户名查询用户（iam_identity_v2.sys_user）。 */
    private final SysUserMapper sysUserMapper;

    /** 权限中心准入决策客户端 (角色供给唯一通道)。 */
    private final AccessDecisionClient accessDecisionClient;

    public PortalUserDetailsService(SysUserMapper sysUserMapper, AccessDecisionClient accessDecisionClient) {
        this.sysUserMapper = sysUserMapper;
        this.accessDecisionClient = accessDecisionClient;
    }

    /** 管理端业务角色编码 (逻辑引用权限中心 sys_role.role_code) */
    private static final String ADMIN_ROLE_CODE = "ADMIN";

    /** 管理服务凭证类别标识: 用户令牌持有者具备管理端角色时发给令牌的 authority */
    private static final String ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";

    /**
     * 按用户名加载用户详情（本地库 iam_identity_v2.sys_user）。
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

    /**
     * 构建用户详情: 凭据与账号状态来自本地 sys_user, 业务角色经 decide 问询权限中心
     * (SWR 缓存), 含 ADMIN 角色时额外注入 ADMIN_SERVICE_TOKEN 令牌类别。
     * 角色供给失败即拒绝登录 (fail-closed, 不猜测)。
     */
    private UserDetails buildUserDetails(SysUser user) {
        String userCode = user.getUserCode();

        Set<String> roles;
        try {
            roles = accessDecisionClient.resolveRoles(userCode);
        } catch (Exception e) {
            log.error("登录准入服务不可用 (无可用缓存判定), fail-closed 拒绝登录 userCode={}", userCode, e);
            throw new InternalAuthenticationServiceException("登录准入服务暂不可用, 请稍后重试", e);
        }

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        if (roles.contains(ADMIN_ROLE_CODE)) {
            authorities.add(new SimpleGrantedAuthority(ADMIN_SERVICE_TOKEN));
        }
        log.debug("用户 {} (user_code={}) RBAC 角色: {}", user.getUsername(), userCode, roles);

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
