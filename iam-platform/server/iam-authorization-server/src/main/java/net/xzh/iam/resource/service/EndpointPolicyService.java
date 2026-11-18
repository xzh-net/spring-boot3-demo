package net.xzh.iam.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.entity.IamEndpointPermission;
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import net.xzh.iam.resource.entity.SysPermission;
import net.xzh.iam.resource.mapper.IamEndpointPermissionMapper;
import net.xzh.iam.resource.mapper.IamEndpointPolicyMapper;
import net.xzh.iam.resource.mapper.SysPermissionMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 资源接口准入策略服务 (iam_endpoint + iam_endpoint_permission, V6.20 拆表).
 * <p>
 * <b>实时直查模式</b>: 每个请求 {@link #findRule} 现查数据库 —— 资源行 → (PERMISSION 行再查) 绑定表
 * → 权限表取当前权限码集合, 与令牌内省口径一致: <b>改权限码零窗口</b>、多实例天然同步、
 * 服务无本地业务内存态 (D4A: 三查直白实现, 档位行只一查)。
 * <p>
 * <b>1:N 权限组合</b> (V6.20): 一个端点可绑 1..N 个权限码, 组合语义 permission_logic —
 * ALL=同时具备 / ANY=任一即可; 档位行 (AUTHENTICATED/PERMIT_ALL) 无绑定留资源表。
 * <p>
 * <b>写入语义</b>: 种子初始化 + 管理页面维护, 资源与绑定<b>两表同一事务</b>提交 (要么都成功要么都回滚);
 * 启动扫描不写库, 仅打配置漂移告警 (不拦截, 配置完整性属运维职责)。
 * <b>Fail-Closed</b>: 查询/绑定/权限解析异常向上抛, 由准入路由器捕获后 deny。
 * </p>
 */
@Slf4j
@Service
public class EndpointPolicyService {

    /** 能力域: 仅作清单推导的 controller 分包判定 (admin=管理端 / biz=业务(门户+三方)) */
    public static final String DOMAIN_ADMIN = "admin";
    public static final String DOMAIN_PORTAL = "portal";
    public static final String DOMAIN_THIRD = "third";

    /** 准入要求档位常量 (放行档, 不可作为权限码授予) */
    public static final String AUTH_PERMIT_ALL = "PERMIT_ALL";
    public static final String AUTH_AUTHENTICATED = "AUTHENTICATED";

    /** 策略类型: 权限码行 (policy_type 取值, 与上面两档常量并列构成三档) */
    public static final String TYPE_PERMISSION = "PERMISSION";

    /** 组合语义: 全部满足 / 任一满足 (permission_logic 取值) */
    public static final String LOGIC_ALL = "ALL";
    public static final String LOGIC_ANY = "ANY";

    /** 服务命名空间固定值 (多服务共表预留; 与 iam.sql 列默认值 / V6.17 默认值三处同步) */
    public static final String SERVICE_KEY = "iam-authorization-server";

    private final IamEndpointPolicyMapper endpointPolicyMapper;
    private final IamEndpointPermissionMapper endpointPermissionMapper;
    private final SysPermissionMapper permissionMapper;
    private final RequestMappingHandlerMapping handlerMapping;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public EndpointPolicyService(IamEndpointPolicyMapper endpointPolicyMapper,
                                 IamEndpointPermissionMapper endpointPermissionMapper,
                                 SysPermissionMapper permissionMapper,
                                 RequestMappingHandlerMapping handlerMapping) {
        this.endpointPolicyMapper = endpointPolicyMapper;
        this.endpointPermissionMapper = endpointPermissionMapper;
        this.permissionMapper = permissionMapper;
        this.handlerMapping = handlerMapping;
    }

    /**
     * 一条已加载的端点规则。
     *
     * @param band          档位 (AUTHENTICATED/PERMIT_ALL); null 表示 PERMISSION 行
     * @param requiredCodes PERMISSION 行所需权限码集合 (档位行为空表)
     * @param logic         ALL=同时具备 / ANY=任一满足 (档位行为 null)
     * @param enabled       false = 停用行, 准入直接拒绝
     */
    public record Rule(String method, String path, String band,
                       List<String> requiredCodes, String logic, boolean enabled) {
    }

    /** 端点标识 (method 大写归一 + Spring 注册模式), 仅用于启动漂移告警比对 */
    private record EndpointKey(String method, String path) {
        static EndpointKey of(String method, String path) {
            return new EndpointKey(method.toUpperCase(), path);
        }

        @Override
        public String toString() {
            return method + " " + path;
        }
    }

    // ==================== 只读查询 ====================

    /** 全量准入行列表 (管理端展示; PERMISSION 行附带 permissionIds 绑定) */
    public List<IamEndpointPolicy> listEndpointPolicies() {
        List<IamEndpointPolicy> rows = endpointPolicyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().orderByAsc("id"));
        if (rows.isEmpty()) {
            return rows;
        }
        Set<Long> epIds = new HashSet<>();
        for (IamEndpointPolicy row : rows) {
            row.setPermissionIds(new ArrayList<>());
            epIds.add(row.getId());
        }
        Map<Long, IamEndpointPolicy> byId = new HashMap<>();
        for (IamEndpointPolicy row : rows) {
            byId.put(row.getId(), row);
        }
        List<IamEndpointPermission> binds = endpointPermissionMapper.selectList(
                new QueryWrapper<IamEndpointPermission>().in("endpoint_id", epIds));
        for (IamEndpointPermission b : binds) {
            IamEndpointPolicy row = byId.get(b.getEndpointId());
            if (row != null && b.getPermissionId() != null) {
                row.getPermissionIds().add(b.getPermissionId());
            }
        }
        return rows;
    }

    // ==================== 实时直查匹配 (每请求, D4A 三查) ====================

    /**
     * 准入匹配 (实时直查): ① 资源行 (method+ANY 过滤) → ② PERMISSION 行再查绑定表 →
     * ③ 权限表取当前权限码集合 (改码零窗口)。未命中返回 null (调用方走认证档)。
     * <p>绑定缺失/权限不可解析 → 抛异常, 由准入路由器捕获后 deny (每请求 Fail-Closed)。</p>
     */
    public Rule findRule(String httpMethod, String requestUri) {
        List<IamEndpointPolicy> rows = endpointPolicyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>()
                        .eq("service_key", SERVICE_KEY)
                        .and(w -> w.eq("method", httpMethod).or().eq("method", "ANY"))
                        .orderByAsc("id"));
        for (IamEndpointPolicy p : rows) {
            if (!pathMatcher.match(p.getPath(), requestUri)) {
                continue;
            }
            boolean enabled = p.getStatus() == null || p.getStatus() == 1;
            if (!TYPE_PERMISSION.equals(p.getPolicyType())) {
                // 档位行: 无绑定, 一查结束
                return new Rule(p.getMethod(), p.getPath(), p.getPolicyType(), List.of(), null, enabled);
            }
            // ② 绑定表 ③ 权限表
            List<IamEndpointPermission> binds = endpointPermissionMapper.selectList(
                    new QueryWrapper<IamEndpointPermission>().eq("endpoint_id", p.getId()));
            if (binds.isEmpty()) {
                throw new IllegalStateException("PERMISSION 行无权限绑定 (policyId=" + p.getId()
                        + ", " + p.getMethod() + " " + p.getPath() + ")");
            }
            List<Long> permIds = new ArrayList<>();
            for (IamEndpointPermission b : binds) {
                if (b.getPermissionId() != null) {
                    permIds.add(b.getPermissionId());
                }
            }
            List<SysPermission> perms = permissionMapper.selectBatchIds(permIds);
            if (perms.size() != permIds.size()) {
                throw new IllegalStateException("权限不可解析 (policyId=" + p.getId()
                        + ", permissionIds=" + permIds + ")");
            }
            List<String> codes = new ArrayList<>();
            for (SysPermission perm : perms) {
                codes.add(perm.getCode());
            }
            String logic = p.getPermissionLogic() == null ? LOGIC_ALL : p.getPermissionLogic();
            return new Rule(p.getMethod(), p.getPath(), null, codes, logic, enabled);
        }
        return null;
    }

    // ==================== 写入 (管理页面维护, 资源+绑定两表同一事务) ====================

    /** 新增准入行 (唯一键 uk_endpoint 由数据库兜底; PERMISSION 行需 permissionIds ≥1) */
    @Transactional
    public IamEndpointPolicy createPolicy(IamEndpointPolicy p) {
        normalize(p);
        validateBinding(p.getPolicyType(), p.getPermissionLogic(), p.getPermissionIds(), true);
        p.setPermissionIds(normalizeIds(p.getPermissionIds()));
        if (TYPE_PERMISSION.equals(p.getPolicyType()) == false) {
            p.setPermissionIds(null); // 档位行无绑定
        }
        p.setCreateTime(java.time.LocalDateTime.now());
        p.setUpdateTime(p.getCreateTime());
        endpointPolicyMapper.insert(p);
        saveBindings(p.getId(), p.getPermissionIds());
        log.info("[EndpointPolicy] 新增准入行 id={}, {} {}, type={}, logic={}, permIds={}",
                p.getId(), p.getMethod(), p.getPath(), p.getPolicyType(),
                p.getPermissionLogic(), p.getPermissionIds());
        return p;
    }

    /**
     * 更新准入行 (方法/路径为身份不可改; 可改档位/权限绑定/组合语义/状态/备注)。
     * permissionIds 语义 = 目标全集 (null=不改动绑定); 档位行绑定强制清空。
     */
    @Transactional
    public IamEndpointPolicy updatePolicy(Long id, IamEndpointPolicy p) {
        IamEndpointPolicy existing = endpointPolicyMapper.selectById(id);
        if (existing == null) {
            throw new IllegalArgumentException("准入行不存在: " + id);
        }
        if (p.getMethod() != null && !p.getMethod().trim().equalsIgnoreCase(existing.getMethod())) {
            throw new IllegalArgumentException("HTTP 方法不可修改 (请删除后重建该准入行)");
        }
        if (p.getPath() != null && !p.getPath().trim().equals(existing.getPath())) {
            throw new IllegalArgumentException("路径不可修改 (请删除后重建该准入行)");
        }
        if (p.getPolicyType() != null) {
            existing.setPolicyType(p.getPolicyType().trim().toUpperCase());
        }
        if (p.getPermissionLogic() != null) {
            existing.setPermissionLogic(p.getPermissionLogic().trim().toUpperCase());
        }
        if (p.getStatus() != null) {
            existing.setStatus(p.getStatus());
        }
        if (p.getRemark() != null) {
            existing.setRemark(p.getRemark());
        }
        boolean permissionRow = TYPE_PERMISSION.equals(existing.getPolicyType());
        if (p.getPermissionIds() == null && permissionRow) {
            // 不传 = 不改动绑定; 但 PERMISSION 行必须保证已有绑定
            Long cnt = endpointPermissionMapper.selectCount(
                    new QueryWrapper<IamEndpointPermission>().eq("endpoint_id", id));
            if (cnt == 0) {
                throw new IllegalArgumentException("权限档 (PERMISSION) 必须指定权限 (当前无绑定)");
            }
        } else if (p.getPermissionIds() != null) {
            validateBinding(existing.getPolicyType(), existing.getPermissionLogic(),
                    p.getPermissionIds(), !permissionRow ? false : true);
            rewriteBindings(id, permissionRow ? normalizeIds(p.getPermissionIds()) : null);
        } else {
            // 档位行且未传 ids → 清空可能残留的绑定
            rewriteBindings(id, null);
        }
        existing.setUpdateTime(java.time.LocalDateTime.now());
        endpointPolicyMapper.updateById(existing);
        log.info("[EndpointPolicy] 更新准入行 id={}, {} {}, type={}, logic={}, status={}, permIds={}",
                existing.getId(), existing.getMethod(), existing.getPath(), existing.getPolicyType(),
                existing.getPermissionLogic(), existing.getStatus(), p.getPermissionIds());
        return existing;
    }

    /** 删除准入行 (endpoint_id CASCADE 自动清绑定; 直查模式下删除即刻对全部实例生效) */
    @Transactional
    public void deletePolicy(Long id) {
        IamEndpointPolicy existing = endpointPolicyMapper.selectById(id);
        if (existing == null) {
            throw new IllegalArgumentException("准入行不存在: " + id);
        }
        endpointPolicyMapper.deleteById(id); // FK CASCADE 清绑定
        log.info("[EndpointPolicy] 删除准入行 id={}, {} {}", id, existing.getMethod(), existing.getPath());
    }

    /** 归一化入参: method 大写、path 前缀、service_key 服务端固定、status 默认 1、logic 默认 ALL */
    private void normalize(IamEndpointPolicy p) {
        if (p.getMethod() == null || p.getMethod().trim().isEmpty()) {
            throw new IllegalArgumentException("HTTP 方法不能为空");
        }
        p.setMethod(p.getMethod().trim().toUpperCase());
        if (p.getPath() == null || p.getPath().trim().isEmpty()) {
            throw new IllegalArgumentException("路径不能为空");
        }
        p.setPath(p.getPath().trim());
        if (!p.getPath().startsWith("/")) {
            throw new IllegalArgumentException("路径须以 / 开头: " + p.getPath());
        }
        if (p.getPolicyType() == null || p.getPolicyType().trim().isEmpty()) {
            throw new IllegalArgumentException("策略类型不能为空");
        }
        p.setPolicyType(p.getPolicyType().trim().toUpperCase());
        if (p.getPermissionLogic() == null || p.getPermissionLogic().trim().isEmpty()) {
            p.setPermissionLogic(LOGIC_ALL);
        } else {
            p.setPermissionLogic(p.getPermissionLogic().trim().toUpperCase());
        }
        p.setServiceKey(SERVICE_KEY); // 服务端固定, 不接受外部传入
        if (p.getStatus() == null) {
            p.setStatus(1);
        }
    }

    /** 校验组合语义与权限绑定 (与策略类型的一致性) */
    private void validateBinding(String type, String logic, List<Long> ids, boolean requireIds) {
        if (!LOGIC_ALL.equals(logic) && !LOGIC_ANY.equals(logic)) {
            throw new IllegalArgumentException("组合方式非法: " + logic + " (可选 ALL / ANY)");
        }
        if (TYPE_PERMISSION.equals(type)) {
            if ((ids == null || ids.isEmpty()) && requireIds) {
                throw new IllegalArgumentException("权限档 (PERMISSION) 必须至少选择一个权限");
            }
            if (ids != null) {
                for (Long pid : ids) {
                    if (pid == null || permissionMapper.selectById(pid) == null) {
                        throw new IllegalArgumentException("权限不存在: " + pid);
                    }
                }
            }
        }
    }

    /** 去重去空 */
    private List<Long> normalizeIds(List<Long> ids) {
        if (ids == null) {
            return null;
        }
        Set<Long> dedup = new LinkedHashSet<>();
        for (Long id : ids) {
            if (id != null) {
                dedup.add(id);
            }
        }
        return new ArrayList<>(dedup);
    }

    /** 事务内写绑定 (全集语义: 先清后插) */
    private void saveBindings(Long endpointId, List<Long> permissionIds) {
        if (permissionIds == null || permissionIds.isEmpty()) {
            return;
        }
        for (Long pid : permissionIds) {
            IamEndpointPermission b = new IamEndpointPermission();
            b.setEndpointId(endpointId);
            b.setPermissionId(pid);
            endpointPermissionMapper.insert(b);
        }
    }

    /** 事务内重写绑定 (null/空 = 清空) */
    private void rewriteBindings(Long endpointId, List<Long> permissionIds) {
        endpointPermissionMapper.delete(new QueryWrapper<IamEndpointPermission>()
                .eq("endpoint_id", endpointId));
        saveBindings(endpointId, permissionIds);
    }

    // ==================== 启动配置漂移告警 (仅告警, 不拦截) ====================

    /**
     * 启动配置漂移检查: 推导白名单域接口清单与资源行比对, 打印缺行/幽灵行/绑定缺失/权限不可解析告警。
     * <b>只告警不拦截</b> (配置完整性属运维职责, 程序不以拒绝启动强制)。
     */
    public void warnConfigDrift() {
        try {
            // 1. 推导接口清单 (与播种白名单同源: admin/biz 两域 + 非基础设施路径)
            Set<EndpointKey> inventory = new HashSet<>();
            for (Map.Entry<RequestMappingInfo, HandlerMethod> entry
                    : handlerMapping.getHandlerMethods().entrySet()) {
                RequestMappingInfo info = entry.getKey();
                HandlerMethod handler = entry.getValue();
                if (resolveDomain(handler.getBeanType().getPackageName()) == null) {
                    continue;
                }
                for (String pattern : extractPatterns(info)) {
                    if (isInfraPath(pattern)) {
                        continue;
                    }
                    Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
                    List<String> methodTokens = methods.isEmpty()
                            ? List.of("ANY")
                            : methods.stream().map(RequestMethod::name).toList();
                    for (String method : methodTokens) {
                        inventory.add(EndpointKey.of(method, pattern));
                    }
                }
            }
            // 2. 资源行比对 (本服务命名空间)
            List<IamEndpointPolicy> rows = endpointPolicyMapper.selectList(
                    new QueryWrapper<IamEndpointPolicy>().eq("service_key", SERVICE_KEY));
            Set<EndpointKey> tableKeys = new HashSet<>();
            List<String> drifts = new ArrayList<>();
            for (IamEndpointPolicy p : rows) {
                EndpointKey key = EndpointKey.of(p.getMethod(), p.getPath());
                if (!tableKeys.add(key)) {
                    drifts.add("重复准入行: " + key + " (policyId=" + p.getId() + ")");
                }
                if (!inventory.contains(key)) {
                    drifts.add("幽灵准入行(表有接口无): " + key + " (policyId=" + p.getId() + ")");
                }
            }
            for (EndpointKey key : inventory) {
                if (!tableKeys.contains(key)) {
                    drifts.add("缺准入行(接口有表无): " + key);
                }
            }
            // 3. PERMISSION 行绑定检查 (绑定数 + 权限存在性)
            List<IamEndpointPolicy> permRows = new ArrayList<>();
            for (IamEndpointPolicy p : rows) {
                if (TYPE_PERMISSION.equals(p.getPolicyType())) {
                    permRows.add(p);
                }
            }
            if (!permRows.isEmpty()) {
                Set<Long> epIds = new HashSet<>();
                for (IamEndpointPolicy p : permRows) {
                    epIds.add(p.getId());
                }
                Map<Long, Integer> bindCount = new HashMap<>();
                Set<Long> permIds = new HashSet<>();
                List<IamEndpointPermission> binds = endpointPermissionMapper.selectList(
                        new QueryWrapper<IamEndpointPermission>().in("endpoint_id", epIds));
                for (IamEndpointPermission b : binds) {
                    bindCount.merge(b.getEndpointId(), 1, Integer::sum);
                    if (b.getPermissionId() != null) {
                        permIds.add(b.getPermissionId());
                    }
                }
                for (IamEndpointPolicy p : permRows) {
                    if (bindCount.getOrDefault(p.getId(), 0) == 0) {
                        drifts.add("PERMISSION 行无权限绑定: " + p.getMethod() + " " + p.getPath()
                                + " (policyId=" + p.getId() + ")");
                    }
                }
                if (!permIds.isEmpty()) {
                    Set<Long> existing = new HashSet<>();
                    for (SysPermission perm : permissionMapper.selectBatchIds(permIds)) {
                        existing.add(perm.getId());
                    }
                    for (IamEndpointPermission b : binds) {
                        if (b.getPermissionId() != null && !existing.contains(b.getPermissionId())) {
                            drifts.add("绑定权限不可解析: policyId=" + b.getEndpointId()
                                    + ", permissionId=" + b.getPermissionId());
                        }
                    }
                }
            }
            // 4. 输出 (只告警, 不拦截启动)
            if (drifts.isEmpty()) {
                log.info("[EndpointPolicy] 启动配置漂移检查: 无漂移 (接口清单 {}, 准入行 {})",
                        inventory.size(), rows.size());
            } else {
                log.warn("[EndpointPolicy] 启动配置漂移告警 ({} 项, 配置完整性属运维职责, 仅提示不拦截):{}",
                        drifts.size(), System.lineSeparator() + "  - "
                                + String.join(System.lineSeparator() + "  - ", drifts));
            }
        } catch (Exception e) {
            log.warn("[EndpointPolicy] 启动配置漂移检查失败 (不影响启动): {}", e.getMessage());
        }
    }

    /** 抽取端点模式 (默认 PathPattern 策略使用 getPatternValues) */
    private Set<String> extractPatterns(RequestMappingInfo info) {
        PathPatternsRequestCondition pathPatterns = info.getPathPatternsCondition();
        if (pathPatterns != null && !pathPatterns.getPatternValues().isEmpty()) {
            return pathPatterns.getPatternValues();
        }
        PatternsRequestCondition patterns = info.getPatternsCondition();
        if (patterns != null) {
            return patterns.getPatterns();
        }
        return Set.of();
    }

    /**
     * 由 controller 分包推导能力域; 清单范围仅 admin / biz 两域 (permitall 链层放行不入表),
     * 域外 (含 permitall 包、平铺控制器、任意杂包) 返回 null 不纳入。
     */
    private String resolveDomain(String packageName) {
        String marker = ".controller.";
        int idx = packageName.indexOf(marker);
        if (idx < 0) {
            return null;
        }
        String segment = packageName.substring(idx + marker.length());
        int dot = segment.indexOf('.');
        String leaf = dot < 0 ? segment : segment.substring(0, dot);
        return switch (leaf) {
            case "admin" -> DOMAIN_ADMIN;
            case "biz" -> DOMAIN_PORTAL;
            case "third" -> DOMAIN_THIRD;
            default -> null;
        };
    }

    /** 基础设施路径 (错误页/健康检查) 不纳入准入点管理 */
    private boolean isInfraPath(String pattern) {
        return pattern.startsWith("/error") || pattern.startsWith("/actuator");
    }
}
