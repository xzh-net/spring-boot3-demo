package net.xzh.iam.resource.service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.auth.entity.OAuth2RegisteredClient;
import net.xzh.iam.auth.entity.SysUser;
import net.xzh.iam.auth.mapper.OAuth2RegisteredClientMapper;
import net.xzh.iam.auth.mapper.SysUserMapper;
import net.xzh.iam.resource.entity.ClientLoginPolicy;
import net.xzh.iam.resource.entity.SysRole;
import net.xzh.iam.resource.mapper.ClientLoginPolicyMapper;
import net.xzh.iam.resource.mapper.SysRoleMapper;

/**
 * 登录准入服务 — 登录维度 (client × 主体) 裁决 + 管理端维护.
 * <p>
 * 与授权维度正交: 本服务只回答「该用户能否登录该客户端」(①签发准入),
 * 不回答「登录后令牌带哪些业务码」(②自省层仍由 用户 RBAC 码 ∩ 客户端 scope 展开码 承担)。
 * <p>
 * <b>运行时判定 {@link #canLogin} (allow-list, fail-closed):</b>
 * <ul>
 *   <li>无任何启用行 → 拒绝 (客户端未配置准入 = 不放行);</li>
 *   <li>{@code ANY} 行 → 放行所有已登录用户 (显式开放, 取代旧逃逸阀);</li>
 *   <li>{@code ROLE} 行 → 用户任一角色命中即放行;</li>
 *   <li>{@code USER} 行 → user_code 精确命中放行;</li>
 *   <li>全部未命中 → 拒绝。</li>
 * </ul>
 * <b>管理端 {@link #listAll} / {@link #replacePolicies}:</b> 供管理页 login_policy.html 使用,
 * 保存为整体覆盖语义 (先删后插, 与 user-roles 绑定一致); 校验主体存在性,
 * 防止「配了但静默不生效」的死配置。
 * <p>
 * 取代 {@code IssuanceAdmissionService} (签发准入=权限码交集, 已随登录/授权解耦移除)。
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAdmissionService {

    private final ClientLoginPolicyMapper clientLoginPolicyMapper;
    private final PermissionService permissionService;
    private final OAuth2RegisteredClientMapper registeredClientMapper;
    private final SysRoleMapper sysRoleMapper;
    private final SysUserMapper sysUserMapper;

    // ------------------------------------------------------------------
    // 运行时判定 (签发准入闸)
    // ------------------------------------------------------------------

    /**
     * 判定用户能否登录 (获发授权码给) 指定客户端.
     *
     * @param clientId 客户端 client_id (授权请求参数)
     * @param userCode 业务用户编码 (令牌 sub, 即授权会话 principal name)
     * @return true=放行签发; false=拒绝 (fail-closed)
     */
    public boolean canLogin(String clientId, String userCode) {
        if (!StringUtils.hasText(clientId) || !StringUtils.hasText(userCode)) {
            return false;
        }
        List<ClientLoginPolicy> rows = clientLoginPolicyMapper.selectList(
                new QueryWrapper<ClientLoginPolicy>()
                        .eq("client_id", clientId)
                        .eq("status", 1));
        if (rows.isEmpty()) {
            log.debug("[登录准入] 无启用准入行 (fail-closed 拒绝): client={}, user={}", clientId, userCode);
            return false;
        }
        List<String> roleCodes = permissionService.findRoleCodes(userCode);
        for (ClientLoginPolicy row : rows) {
            String type = row.getSubjectType() == null ? "" : row.getSubjectType().toUpperCase();
            if ("ANY".equals(type)) {
                log.debug("[登录准入] ANY 行放行: client={}, user={}", clientId, userCode);
                return true;
            }
            if ("ROLE".equals(type) && roleCodes.contains(row.getSubjectId())) {
                log.debug("[登录准入] ROLE 命中放行: client={}, user={}, role={}",
                        clientId, userCode, row.getSubjectId());
                return true;
            }
            if ("USER".equals(type) && userCode.equals(row.getSubjectId())) {
                log.debug("[登录准入] USER 命中放行: client={}, user={}", clientId, userCode);
                return true;
            }
        }
        log.debug("[登录准入] 未命中任何启用主体 (拒绝): client={}, user={}, roles={}",
                clientId, userCode, roleCodes);
        return false;
    }

    // ------------------------------------------------------------------
    // 管理端 (login_policy.html)
    // ------------------------------------------------------------------

    /** 全量准入行 (管理页), 按 client_id / 主体排序; 客户端是否有行由页面合并 /admin/clients 得出 */
    public List<ClientLoginPolicy> listAll() {
        return clientLoginPolicyMapper.selectList(new QueryWrapper<ClientLoginPolicy>()
                .orderByAsc("client_id")
                .orderByAsc("subject_type")
                .orderByAsc("subject_id"));
    }

    /**
     * 整体覆盖某客户端的准入行 (先删后插, 事务).
     * <p>
     * 空列表 = 清空该客户端准入 → 之后所有登录被拒 (fail-closed), 页面须二次确认。
     * 校验: 客户端已注册 / 主体类型合法 / ROLE·USER 主体存在 / 无重复行 / status 合法。
     * </p>
     *
     * @param clientId 目标客户端 client_id
     * @param rows     该客户端的完整准入行 (id / createTime 由服务端重置)
     */
    @Transactional
    public void replacePolicies(String clientId, List<ClientLoginPolicy> rows) {
        if (!StringUtils.hasText(clientId)) {
            throw new IllegalArgumentException("clientId 不能为空");
        }
        // 客户端须已注册 (防配到不存在的 client_id 上; client_id 无唯一约束, 故用 selectList 判空)
        if (registeredClientMapper.selectList(new QueryWrapper<OAuth2RegisteredClient>()
                .eq("client_id", clientId)).isEmpty()) {
            throw new IllegalArgumentException("客户端不存在: " + clientId);
        }
        List<ClientLoginPolicy> normalized = normalize(clientId, rows);

        clientLoginPolicyMapper.delete(new QueryWrapper<ClientLoginPolicy>().eq("client_id", clientId));
        for (ClientLoginPolicy row : normalized) {
            clientLoginPolicyMapper.insert(row);
        }
        log.info("[登录准入] 覆盖保存: client={}, 行数={}, 主体={}",
                clientId, normalized.size(),
                normalized.stream().map(r -> r.getSubjectType() + ":" + r.getSubjectId()).toList());
    }

    /** 规范化 + 校验 (类型大写、ANY 强制空 subjectId、主体存在性、去重、status) */
    private List<ClientLoginPolicy> normalize(String clientId, List<ClientLoginPolicy> rows) {
        List<ClientLoginPolicy> out = new ArrayList<>();
        if (rows == null || rows.isEmpty()) {
            return out;
        }
        Set<String> seen = new HashSet<>();
        for (ClientLoginPolicy r : rows) {
            if (r == null) {
                continue;
            }
            String type = r.getSubjectType() == null ? "" : r.getSubjectType().trim().toUpperCase();
            if (!"ROLE".equals(type) && !"USER".equals(type) && !"ANY".equals(type)) {
                throw new IllegalArgumentException("主体类型仅支持 ROLE / USER / ANY: " + r.getSubjectType());
            }
            String subjectId = "ANY".equals(type) ? ""
                    : (r.getSubjectId() == null ? "" : r.getSubjectId().trim());
            if (!"ANY".equals(type) && subjectId.isEmpty()) {
                throw new IllegalArgumentException(type + " 主体的 subjectId 不能为空");
            }
            // 主体存在性: 防止打错码导致「配了但静默不生效」的死配置
            if ("ROLE".equals(type) && sysRoleMapper.selectList(new QueryWrapper<SysRole>()
                    .eq("code", subjectId)).isEmpty()) {
                throw new IllegalArgumentException("角色不存在: " + subjectId);
            }
            if ("USER".equals(type) && sysUserMapper.selectList(new QueryWrapper<SysUser>()
                    .eq("user_code", subjectId)).isEmpty()) {
                throw new IllegalArgumentException("用户不存在 (user_code): " + subjectId);
            }
            if (!seen.add(type + ":" + subjectId)) {
                throw new IllegalArgumentException("重复的准入行: " + type + " " + subjectId);
            }
            Integer status = r.getStatus() == null ? 1 : r.getStatus();
            if (status != 0 && status != 1) {
                throw new IllegalArgumentException("status 仅支持 0 / 1");
            }
            ClientLoginPolicy row = new ClientLoginPolicy();
            row.setClientId(clientId);
            row.setSubjectType(type);
            row.setSubjectId(subjectId);
            row.setStatus(status);
            row.setRemark(r.getRemark());
            out.add(row);
        }
        return out;
    }
}
