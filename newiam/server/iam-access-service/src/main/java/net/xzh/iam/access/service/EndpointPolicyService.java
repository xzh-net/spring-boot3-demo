package net.xzh.iam.access.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.access.entity.IamEndpointPolicy;
import net.xzh.iam.access.mapper.IamEndpointPolicyMapper;
import org.springframework.stereotype.Service;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 资源接口准入策略服务 (iam_endpoint_policy).
 * <p>
 * 职责: 启动扫描播种 (coded) / 管理端覆盖 (override) / 内存快照匹配裁决。
 * 快照仅载入启用行, 准入路由器按 method + Ant 路径匹配; 未命中即默认拒绝 (deny-by-default)。
 * <p>
 * 特殊域: internal 域为<b>硬规则</b> (仅认证中心 M2M 可调, 见
 * {@link net.xzh.iam.access.config.EndpointAdmissionManager}), 不进入本规则表; 扫描会跳过
 * internal 域播种并将该域残留行 (含历史/override) 一并清理。
 * </p>
 */
@Slf4j
@Service
public class EndpointPolicyService {

    private final IamEndpointPolicyMapper policyMapper;
    private final RequestMappingHandlerMapping handlerMapping;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 启用规则快照 (volatile: 管理端变更后刷新) */
    private volatile List<Rule> snapshot = List.of();

    public EndpointPolicyService(IamEndpointPolicyMapper policyMapper,
                                 RequestMappingHandlerMapping handlerMapping) {
        this.policyMapper = policyMapper;
        this.handlerMapping = handlerMapping;
    }

    /** 一条已加载的启用规则 */
    public record Rule(String domain, String method, String path, String requiredAuthority) {
    }

    /**
     * 启动扫描播种: 按 RequestMapping 遍历全部控制器端点, 依据 controller 分包推导默认准入规则,
     * 缺失则补种 (source=coded)。已存在的行 (含 override) 不覆盖。完成后刷新内存快照。
     * internal 域跳过播种 (硬规则域, 见类注); 该域残留行整域清理。
     *
     * @return 本次新增条数
     */
    public synchronized int rescan() {
        int inserted = 0;
        Set<String> scannedKeys = new HashSet<>();
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry
                : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            HandlerMethod handler = entry.getValue();

            try {
                String packageName = handler.getBeanType().getPackageName();
                String domain = resolveDomain(packageName);

                // internal 域为硬规则 (仅认证中心 M2M 可调, 见 EndpointAdmissionManager),
                // 不进入规则表, 也不参与扫码播种 / 管理端 override
                if (IamEndpointPolicy.DOMAIN_INTERNAL.equals(domain)) {
                    continue;
                }

                String defaultAuthority = defaultAuthorityOf(packageName, domain);

                Set<String> patterns = extractPatterns(info);
                Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
                List<String> methodTokens = methods.isEmpty()
                        ? List.of("ANY")
                        : methods.stream().map(RequestMethod::name).toList();

                for (String pattern : patterns) {
                    if (isInfraPath(pattern)) {
                        continue;
                    }
                    for (String method : methodTokens) {
                        scannedKeys.add(method + "|" + pattern);
                        IamEndpointPolicy existing = policyMapper.selectOne(new QueryWrapper<IamEndpointPolicy>()
                                .eq("method", method).eq("path", pattern));
                        if (existing == null) {
                            IamEndpointPolicy policy = new IamEndpointPolicy();
                            policy.setDomain(domain);
                            policy.setMethod(method);
                            policy.setPath(pattern);
                            policy.setRequiredAuthority(defaultAuthority);
                            policy.setSource(IamEndpointPolicy.SOURCE_CODED);
                            policy.setStatus(1);
                            policyMapper.insert(policy);
                            inserted++;
                        } else if (IamEndpointPolicy.SOURCE_CODED.equals(existing.getSource())
                                && (!defaultAuthority.equals(existing.getRequiredAuthority())
                                || !domain.equals(existing.getDomain()))) {
                            // coded 默认随代码版本自动对齐 (管理端 override 一律不动)
                            existing.setDomain(domain);
                            existing.setRequiredAuthority(defaultAuthority);
                            policyMapper.updateById(existing);
                            log.info("[EndpointPolicy] 对齐 coded 默认: {} {} -> {}/{}", method, pattern, domain, defaultAuthority);
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("[EndpointPolicy] 跳过端点 {}: {}", handler, e.getMessage());
            }
        }

        // internal 域为硬规则 (仅认证中心 M2M 可调): 整域清理, 不渲染进规则表 (含历史/override 残留)
        int internalRemoved = 0;
        for (IamEndpointPolicy p : policyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().eq("domain", IamEndpointPolicy.DOMAIN_INTERNAL))) {
            policyMapper.deleteById(p.getId());
            internalRemoved++;
        }
        if (internalRemoved > 0) {
            log.info("[EndpointPolicy] 清理 internal 硬规则域残留行 {} 条 (不参与规则表)", internalRemoved);
        }

        // 清理失效 coded 行: 端点已从代码移除 (如废弃接口删除) 时, 旧扫描播种的行不再对应任何
        // 注册端点, 一并删除 (管理端 override 行一律保留)。
        Map<String, IamEndpointPolicy> codedByKey = new HashMap<>();
        for (IamEndpointPolicy p : policyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().eq("source", IamEndpointPolicy.SOURCE_CODED))) {
            codedByKey.put(p.getMethod() + "|" + p.getPath(), p);
        }
        int pruned = 0;
        for (String key : codedByKey.keySet()) {
            if (!scannedKeys.contains(key)) {
                policyMapper.deleteById(codedByKey.get(key).getId());
                pruned++;
            }
        }
        if (pruned > 0) {
            log.info("[EndpointPolicy] 清理失效 coded 准入点 {} 条", pruned);
        }

        reloadSnapshot();
        log.info("[EndpointPolicy] 扫描播种完成: 本次新增 {} 条, 清理 {} 条, 当前启用规则 {} 条",
                inserted, pruned, snapshot.size());
        return inserted;
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

    /** 由 controller 分包推导能力域 (net.xzh.iam.access.controller.admin.Xxx → admin) */
    private String resolveDomain(String packageName) {
        String marker = ".controller.";
        int idx = packageName.indexOf(marker);
        if (idx < 0) {
            return IamEndpointPolicy.DOMAIN_OTHER;
        }
        String segment = packageName.substring(idx + marker.length());
        int dot = segment.indexOf('.');
        String leaf = dot < 0 ? segment : segment.substring(0, dot);
        return switch (leaf) {
            case "admin" -> IamEndpointPolicy.DOMAIN_ADMIN;
            case "portal" -> IamEndpointPolicy.DOMAIN_PORTAL;
            case "internal" -> IamEndpointPolicy.DOMAIN_INTERNAL;
            // 放行示例包 (controller/permitall) 不再单列能力域, 归 other (其他),
            // 但其默认准入要求仍为 PERMIT_ALL, 见 defaultAuthorityOf。
            default -> IamEndpointPolicy.DOMAIN_OTHER;
        };
    }

    /** 各能力域默认准入规则 (扫描播种默认值) */
    private String defaultAuthorityOf(String packageName, String domain) {
        if ("permitall".equals(controllerLeaf(packageName))) {
            return IamEndpointPolicy.AUTH_PERMIT_ALL;
        }
        return switch (domain) {
            case IamEndpointPolicy.DOMAIN_ADMIN -> IamEndpointPolicy.AUTH_ADMIN_SERVICE_TOKEN;
            case IamEndpointPolicy.DOMAIN_INTERNAL -> IamEndpointPolicy.AUTH_PORTAL_SERVICE_TOKEN;
            case IamEndpointPolicy.DOMAIN_PORTAL -> IamEndpointPolicy.AUTH_PORTAL_SERVICE_TOKEN;
            default -> IamEndpointPolicy.AUTH_AUTHENTICATED;
        };
    }

    /** 取 controller 分包首段 (net.xzh.iam.access.controller.admin.Xxx → admin) */
    private String controllerLeaf(String packageName) {
        String marker = ".controller.";
        int idx = packageName.indexOf(marker);
        if (idx < 0) {
            return "";
        }
        String segment = packageName.substring(idx + marker.length());
        int dot = segment.indexOf('.');
        return dot < 0 ? segment : segment.substring(0, dot);
    }

    /** 基础设施路径 (错误页/健康检查) 不纳入准入点管理 */
    private boolean isInfraPath(String pattern) {
        return pattern.startsWith("/error") || pattern.startsWith("/actuator");
    }

    /** 全部行 (含停用, 供管理页) */
    public List<IamEndpointPolicy> listAll() {
        return policyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().orderByAsc("domain", "method", "path"));
    }

    public IamEndpointPolicy getById(Long id) {
        return policyMapper.selectById(id);
    }

    /** 管理端覆盖: 保存扫描默认以外的偏好, 置 source=override 并刷新快照 */
    public IamEndpointPolicy updatePolicy(Long id, String requiredAuthority, Integer status, String remark) {
        IamEndpointPolicy policy = policyMapper.selectById(id);
        if (policy == null) {
            throw new IllegalArgumentException("策略不存在: " + id);
        }
        if (!validAuthority(requiredAuthority)) {
            throw new IllegalArgumentException("准入要求不合法: " + requiredAuthority);
        }
        policy.setRequiredAuthority(requiredAuthority);
        policy.setStatus(status == null ? 1 : status);
        policy.setRemark(remark);
        policy.setSource(IamEndpointPolicy.SOURCE_OVERRIDE);
        policyMapper.updateById(policy);
        reloadSnapshot();
        return policyMapper.selectById(id);
    }

    /** 重置为扫描默认: 删除当前行, 由 rescan 按分包推导回补 coded 规则 */
    public synchronized void resetToCoded(Long id) {
        if (policyMapper.selectById(id) != null) {
            policyMapper.deleteById(id);
        }
        rescan();
    }

    private boolean validAuthority(String authority) {
        return Set.of(
                IamEndpointPolicy.AUTH_PERMIT_ALL,
                IamEndpointPolicy.AUTH_AUTHENTICATED,
                IamEndpointPolicy.AUTH_ADMIN_SERVICE_TOKEN,
                IamEndpointPolicy.AUTH_PORTAL_SERVICE_TOKEN
        ).contains(authority);
    }

    /** 刷新启用规则内存快照 */
    public synchronized void reloadSnapshot() {
        List<IamEndpointPolicy> enabled = policyMapper.selectList(
                new QueryWrapper<IamEndpointPolicy>().eq("status", 1));
        List<Rule> rules = new ArrayList<>(enabled.size());
        for (IamEndpointPolicy p : enabled) {
            rules.add(new Rule(p.getDomain(), p.getMethod(), p.getPath(), p.getRequiredAuthority()));
        }
        snapshot = List.copyOf(rules);
    }

    /**
     * 准入匹配: 返回首个 (method, path) 命中的启用规则; 未命中返回 null (调用方默认拒绝)。
     * Ant 匹配兼容 Spring 注册模式 (如 /api/admin/permissions/{id} 中的 {id} 视为单段通配)。
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