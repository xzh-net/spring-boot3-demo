package net.xzh.iam.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import net.xzh.iam.resource.mapper.IamEndpointPolicyMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 资源接口准入策略服务 (iam_endpoint_policy).
 * <p>
 * 职责: 启动扫描播种 (source=coded, 域默认粗档) / 内存快照匹配裁决 / 管理端 CRUD。
 * 快照载入全部准入行 (含 status=0 停用行, 以 enabled 标记, 停用=准入拒绝), 准入路由器按
 * method + Ant 路径匹配。
 * <p>
 * 播种白名单: 仅 admin / portal / third 三域入库 (需要控制的端点); 域外端点
 * (/api/permitall/** 由链层放行, 其余 /api/** 走认证档) 不播种, 失效 coded 行随剪除清理。
 * 管理端 override 行 (含手工建行与码化端点) 一律不被对齐/剪除; 手工建/编辑一律置 override。
 * </p>
 */
@Slf4j
@Service
public class EndpointPolicyService {

    /** 能力域: admin=管理端 / portal=门户 / third=三方 */
    public static final String DOMAIN_ADMIN = "admin";
    public static final String DOMAIN_PORTAL = "portal";
    public static final String DOMAIN_THIRD = "third";

    /** 准入要求粗档常量 (令牌类别/放行档, 不可作为权限码授予) */
    public static final String AUTH_PERMIT_ALL = "PERMIT_ALL";
    public static final String AUTH_AUTHENTICATED = "AUTHENTICATED";
    public static final String AUTH_ADMIN_SERVICE_TOKEN = "ADMIN_SERVICE_TOKEN";
    public static final String AUTH_PORTAL_SERVICE_TOKEN = "PORTAL_SERVICE_TOKEN";

    /** 来源: coded=启动扫描播种 / override=管理端覆盖 (rescan 跳过) */
    public static final String SOURCE_CODED = "coded";
    public static final String SOURCE_OVERRIDE = "override";

    private final IamEndpointPolicyMapper endpointPolicyMapper;
    private final RequestMappingHandlerMapping handlerMapping;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 端点规则快照 (volatile: 管理端变更后刷新) */
    private volatile List<Rule> snapshot = List.of();

    public EndpointPolicyService(IamEndpointPolicyMapper endpointPolicyMapper,
                                 RequestMappingHandlerMapping handlerMapping) {
        this.endpointPolicyMapper = endpointPolicyMapper;
        this.handlerMapping = handlerMapping;
    }

    /** 一条已加载的端点规则 (enabled=false 表示停用行, 准入直接拒绝) */
    public record Rule(String domain, String method, String path, String requiredAuthority, boolean enabled) {
    }

    // ==================== 管理端 CRUD ====================

    /** 全量准入行列表 (管理端左栏资源列表) */
    public List<IamEndpointPolicy> listEndpointPolicies() {
        return endpointPolicyMapper.selectList(new QueryWrapper<IamEndpointPolicy>().orderByAsc("id"));
    }

    /** 新增资源准入行 (手工建行一律 override, rescan 跳过) */
    @Transactional(rollbackFor = Exception.class)
    public IamEndpointPolicy createEndpointPolicy(IamEndpointPolicy policy) {
        if (!StringUtils.hasText(policy.getPath())) {
            throw new IllegalArgumentException("路径必填");
        }
        if (!StringUtils.hasText(policy.getRequiredAuthority())) {
            throw new IllegalArgumentException("准入要求不能为空 (权限码或粗档常量)");
        }
        policy.setPath(policy.getPath().trim());
        if (!StringUtils.hasText(policy.getMethod())) {
            policy.setMethod("ANY");
        }
        policy.setMethod(policy.getMethod().trim().toUpperCase(Locale.ROOT));
        if (!StringUtils.hasText(policy.getDomain())) {
            policy.setDomain(DOMAIN_ADMIN);
        }
        if (policy.getStatus() == null) {
            policy.setStatus(1);
        }
        policy.setRequiredAuthority(policy.getRequiredAuthority().trim());
        policy.setSource(SOURCE_OVERRIDE);
        if (endpointPolicyMapper.selectCount(new QueryWrapper<IamEndpointPolicy>()
                .eq("method", policy.getMethod()).eq("path", policy.getPath())) > 0) {
            throw new IllegalArgumentException("端点准入已存在: " + policy.getMethod() + " " + policy.getPath());
        }
        policy.setCreateTime(LocalDateTime.now());
        policy.setUpdateTime(policy.getCreateTime());
        endpointPolicyMapper.insert(policy);
        reloadSnapshot();
        log.info("[EndpointPolicy] 新增准入行 id={}, {} {}, 准入={}, source={}",
                policy.getId(), policy.getMethod(), policy.getPath(),
                policy.getRequiredAuthority(), policy.getSource());
        return policy;
    }

    /** 编辑准入行 (编辑即覆盖: source 置 override, rescan 不再回写) */
    @Transactional(rollbackFor = Exception.class)
    public void updateEndpointPolicy(Long id, IamEndpointPolicy policy) {
        IamEndpointPolicy existing = endpointPolicyMapper.selectById(id);
        if (existing == null) {
            throw new IllegalArgumentException("准入行不存在: " + id);
        }
        if (StringUtils.hasText(policy.getPath())) {
            existing.setPath(policy.getPath().trim());
        }
        if (StringUtils.hasText(policy.getMethod())) {
            existing.setMethod(policy.getMethod().trim().toUpperCase(Locale.ROOT));
        }
        if (StringUtils.hasText(policy.getRequiredAuthority())) {
            existing.setRequiredAuthority(policy.getRequiredAuthority().trim());
        }
        if (StringUtils.hasText(policy.getDomain())) {
            existing.setDomain(policy.getDomain());
        }
        if (policy.getStatus() != null) {
            existing.setStatus(policy.getStatus());
        }
        if (policy.getRemark() != null) {
            existing.setRemark(policy.getRemark());
        }
        if (endpointPolicyMapper.selectCount(new QueryWrapper<IamEndpointPolicy>()
                .eq("method", existing.getMethod()).eq("path", existing.getPath()).ne("id", id)) > 0) {
            throw new IllegalArgumentException("端点准入已存在: " + existing.getMethod() + " " + existing.getPath());
        }
        existing.setSource(SOURCE_OVERRIDE);
        existing.setUpdateTime(LocalDateTime.now());
        endpointPolicyMapper.updateById(existing);
        reloadSnapshot();
        log.info("[EndpointPolicy] 更新准入行 id={}, {} {}, 准入={}, status={}",
                id, existing.getMethod(), existing.getPath(),
                existing.getRequiredAuthority(), existing.getStatus());
    }

    /**
     * 删除准入行。
     * <p>
     * 删除守卫: 对应运行中 controller 端点的行不可删 (coded 行重启会被扫描重建,
     * override 行被删后准入降级为认证档, 安全姿态静默变化), 请改用停用/修改准入要求;
     * 非活端点行 (占位路径/已下线接口遗留) 允许删除。
     * </p>
     */
    @Transactional(rollbackFor = Exception.class)
    public void deleteEndpointPolicy(Long id) {
        IamEndpointPolicy existing = endpointPolicyMapper.selectById(id);
        if (existing == null) {
            throw new IllegalArgumentException("准入行不存在: " + id);
        }
        if (isLiveEndpoint(existing.getPath())) {
            throw new IllegalArgumentException("该行对应运行中接口 ("
                    + existing.getMethod() + " " + existing.getPath()
                    + "), 删除会被启动扫描重建或导致准入降级, 请改用「停用」或修改准入要求");
        }
        endpointPolicyMapper.deleteById(id);
        reloadSnapshot();
        log.info("[EndpointPolicy] 删除准入行 id={}, {} {}", id, existing.getMethod(), existing.getPath());
    }

    // ==================== 启动扫描播种 ====================

    /**
     * 启动扫描播种: 按 RequestMapping 遍历全部控制器端点, 依据 controller 分包推导默认准入规则,
     * 缺失则补种 (source=coded, 域默认粗档)。已存在的行 (含 override) 不覆盖; coded 默认随代码
     * 版本自动对齐。完成后刷新内存快照与存活端点集。
     *
     * @return 本次新增条数
     */
    public synchronized int rescan() {
        int inserted = 0;
        Set<String> scannedKeys = new HashSet<>();
        Set<String> scannedPaths = new HashSet<>();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry
                : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            HandlerMethod handler = entry.getValue();

            try {
                String packageName = handler.getBeanType().getPackageName();
                String domain = resolveDomain(packageName);

                // 播种白名单: 仅 admin / portal / third 三域入库; 域外端点
                // (/api/permitall/** 链层放行, 其余 /api/** 走认证档) 不进入规则表
                if (domain == null) {
                    continue;
                }

                String defaultAuthority = defaultAuthorityOf(domain);

                Set<String> patterns = extractPatterns(info);
                Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
                List<String> methodTokens = methods.isEmpty()
                        ? List.of("ANY")
                        : methods.stream().map(RequestMethod::name).toList();

                for (String pattern : patterns) {
                    if (isInfraPath(pattern)) {
                        continue;
                    }
                    scannedPaths.add(pattern);
                    for (String method : methodTokens) {
                        scannedKeys.add(method + "|" + pattern);
                        IamEndpointPolicy existing = endpointPolicyMapper.selectOne(
                                new QueryWrapper<IamEndpointPolicy>()
                                        .eq("method", method).eq("path", pattern));
                        if (existing == null) {
                            IamEndpointPolicy row = new IamEndpointPolicy();
                            row.setDomain(domain);
                            row.setMethod(method);
                            row.setPath(pattern);
                            row.setRequiredAuthority(defaultAuthority);
                            row.setSource(SOURCE_CODED);
                            row.setStatus(1);
                            endpointPolicyMapper.insert(row);
                            inserted++;
                        } else if (SOURCE_CODED.equals(existing.getSource())
                                && (!defaultAuthority.equals(existing.getRequiredAuthority())
                                || !domain.equals(existing.getDomain()))) {
                            // coded 默认随代码版本自动对齐 (管理端 override 一律不动)
                            existing.setDomain(domain);
                            existing.setRequiredAuthority(defaultAuthority);
                            endpointPolicyMapper.updateById(existing);
                            log.info("[EndpointPolicy] 对齐 coded 默认: {} {} -> {}/{}",
                                    method, pattern, domain, defaultAuthority);
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("[EndpointPolicy] 跳过端点 {}: {}", handler, e.getMessage());
            }
        }

        // 清理失效 coded 行: 端点已从代码移除 (如废弃接口删除) 时, 旧扫描播种的行不再对应任何
        // 注册端点, 一并删除 (管理端 override 行一律保留)。
        Map<String, IamEndpointPolicy> codedByKey = new HashMap<>();
        for (IamEndpointPolicy p : endpointPolicyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().eq("source", SOURCE_CODED))) {
            codedByKey.put(p.getMethod() + "|" + p.getPath(), p);
        }
        int pruned = 0;
        for (String key : codedByKey.keySet()) {
            if (!scannedKeys.contains(key)) {
                endpointPolicyMapper.deleteById(codedByKey.get(key).getId());
                pruned++;
            }
        }
        if (pruned > 0) {
            log.info("[EndpointPolicy] 清理失效 coded 准入点 {} 条", pruned);
        }

        livePaths = Set.copyOf(scannedPaths);
        reloadSnapshot();
        log.info("[EndpointPolicy] 扫描播种完成: 本次新增 {} 条, 清理 {} 条, 当前端点规则 {} 条",
                inserted, pruned, snapshot.size());
        return inserted;
    }

    /** 上次扫描发现的存活端点路径集 (删除守卫用: 活端点行不可删, 见 deleteEndpointPolicy) */
    private volatile Set<String> livePaths = Set.of();

    /** 存活端点判定: 路径是否对应上次扫描发现的控制器端点 (删除守卫) */
    public boolean isLiveEndpoint(String path) {
        return path != null && livePaths.contains(path);
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
     * 由 controller 分包推导能力域; 播种白名单仅 admin / portal / third 三域,
     * 域外 (含 permitall 包、平铺控制器、任意杂包) 返回 null 不入库。
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
            case "portal" -> DOMAIN_PORTAL;
            case "third" -> DOMAIN_THIRD;
            default -> null;
        };
    }

    /** 各能力域默认准入规则 (扫描播种默认值, 均为粗档) */
    private String defaultAuthorityOf(String domain) {
        return switch (domain) {
            case DOMAIN_ADMIN -> AUTH_ADMIN_SERVICE_TOKEN;
            case DOMAIN_PORTAL -> AUTH_PORTAL_SERVICE_TOKEN;
            default -> AUTH_AUTHENTICATED;
        };
    }

    /** 基础设施路径 (错误页/健康检查) 不纳入准入点管理 */
    private boolean isInfraPath(String pattern) {
        return pattern.startsWith("/error") || pattern.startsWith("/actuator");
    }

    /**
     * 刷新端点规则内存快照: 载入全部准入行 (含停用行, enabled=false → 准入拒绝)。
     */
    public synchronized void reloadSnapshot() {
        List<IamEndpointPolicy> rows = endpointPolicyMapper.selectList(new QueryWrapper<>());
        List<Rule> rules = new ArrayList<>(rows.size());
        for (IamEndpointPolicy p : rows) {
            rules.add(new Rule(p.getDomain(), p.getMethod(), p.getPath(), p.getRequiredAuthority(),
                    p.getStatus() == null || p.getStatus() == 1));
        }
        snapshot = List.copyOf(rules);
    }

    /**
     * 准入匹配: 返回首个 (method, path) 命中的端点规则 (含停用行); 未命中返回 null (调用方走认证档)。
     * 命中停用行由调用方按 enabled=false 拒绝。Ant 匹配兼容 Spring 注册模式。
     */
    public Rule findRule(String httpMethod, String requestUri) {
        for (Rule rule : snapshot) {
            if (!rule.method().equalsIgnoreCase("ANY")
                    && !rule.method().equalsIgnoreCase(httpMethod)) {
                continue;
            }
            if (pathMatcher.match(rule.path(), requestUri)) {
                return rule;
            }
        }
        return null;
    }
}
