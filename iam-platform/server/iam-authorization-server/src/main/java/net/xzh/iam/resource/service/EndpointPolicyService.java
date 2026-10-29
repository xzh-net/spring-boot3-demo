package net.xzh.iam.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.resource.entity.IamEndpointPolicy;
import net.xzh.iam.resource.mapper.IamEndpointPolicyMapper;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PatternsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 资源接口准入策略服务 (iam_endpoint_policy).
 * <p>
 * 职责: 启动自扫描补缺 / 内存快照匹配裁决 / 只读列表查询。
 * 快照载入全部准入行 (含 status=0 停用行, 以 enabled 标记, 停用=准入拒绝), 准入路由器按
 * method + Ant 路径匹配。
 * <p>
 * <b>写入语义 (本表唯一写入方=启动自扫描)</b>:
 * <ul>
 *   <li>精确权限码 (user:read 等) 的权威=iam.sql 种子, 扫描<b>不回写</b> authority;</li>
 *   <li>扫描只做两件事: 代码里新增的端点补入库 (默认 AUTHENTICATED) / 代码里已删除端点的行剪除;</li>
 *   <li>管理端<b>无</b>新增/编辑/删除入口, 页面只读 (domain/source 两列已删)。</li>
 * </ul>
 * 播种白名单: 仅 admin / biz 两域 controller 包的端点入库; 域外端点
 * (/permitall/** 由链层放行, 三前缀之外不入链) 不入表。
 * 粗档常量 (ADMIN_SERVICE_TOKEN / PORTAL_SERVICE_TOKEN) 已退役: 准入要求全部为权限码或放行档。
 * </p>
 */
@Slf4j
@Service
public class EndpointPolicyService {

    /** 能力域: 仅作播种白名单的 controller 分包判定 (admin=管理端 / biz=业务(门户+三方)) */
    public static final String DOMAIN_ADMIN = "admin";
    public static final String DOMAIN_PORTAL = "portal";
    public static final String DOMAIN_THIRD = "third";

    /** 准入要求档位常量 (放行档, 不可作为权限码授予); 粗档服务令牌常量已退役 */
    public static final String AUTH_PERMIT_ALL = "PERMIT_ALL";
    public static final String AUTH_AUTHENTICATED = "AUTHENTICATED";

    private final IamEndpointPolicyMapper endpointPolicyMapper;
    private final RequestMappingHandlerMapping handlerMapping;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 端点规则快照 (volatile: 扫描变更后刷新) */
    private volatile List<Rule> snapshot = List.of();

    public EndpointPolicyService(IamEndpointPolicyMapper endpointPolicyMapper,
                                 RequestMappingHandlerMapping handlerMapping) {
        this.endpointPolicyMapper = endpointPolicyMapper;
        this.handlerMapping = handlerMapping;
    }

    /** 一条已加载的端点规则 (enabled=false 表示停用行, 准入直接拒绝) */
    public record Rule(String method, String path, String requiredAuthority, boolean enabled) {
    }

    // ==================== 只读查询 ====================

    /** 全量准入行列表 (管理端展示) */
    public List<IamEndpointPolicy> listEndpointPolicies() {
        return endpointPolicyMapper.selectList(new QueryWrapper<IamEndpointPolicy>().orderByAsc("id"));
    }

    // ==================== 启动自扫描 (唯一写入方) ====================


    /**
     * 启动自扫描补缺: 按 RequestMapping 遍历全部控制器端点, 依据 controller 分包判定播种白名单,
     * 库里缺失的端点补入 (authority 用宽松默认 AUTHENTICATED)。已存在的行一律不动 ——
     * 不回写 authority (精确码权威=iam.sql 种子)、不剪除 (domain/source 已删, 无所有权信息)。
     *
     * @return 本次新增条数
     */
    public synchronized int rescan() {
        int inserted = 0;
        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry
                : handlerMapping.getHandlerMethods().entrySet()) {
            RequestMappingInfo info = entry.getKey();
            HandlerMethod handler = entry.getValue();

            try {
                String packageName = handler.getBeanType().getPackageName();
                String domain = resolveDomain(packageName);

                // 播种白名单: 仅 admin / biz 两域 controller 包的端点入库;
                // 域外端点 (/permitall/** 链层放行, 三前缀之外不入链) 不入表
                if (domain == null) {
                    continue;
                }

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
                        IamEndpointPolicy existing = endpointPolicyMapper.selectOne(
                                new QueryWrapper<IamEndpointPolicy>()
                                        .eq("method", method).eq("path", pattern));
                        if (existing == null) {
                            // 新端点补入库: authority 用宽松默认 AUTHENTICATED, 精确码须由种子提供
                            IamEndpointPolicy row = new IamEndpointPolicy();
                            row.setMethod(method);
                            row.setPath(pattern);
                            row.setRequiredAuthority(AUTH_AUTHENTICATED);
                            row.setStatus(1);
                            endpointPolicyMapper.insert(row);
                            inserted++;
                        }
                        // 已存在行一律不动: 不回写 authority (种子为权威), 不剪除
                        // (domain/source 两列已删, 无法区分种子行与扫描行, 全量剪除可能误删存活细码行)
                    }
                }
            } catch (Exception e) {
                log.warn("[EndpointPolicy] 跳过端点 {}: {}", handler, e.getMessage());
            }
        }

        reloadSnapshot();
        log.info("[EndpointPolicy] 自扫描补缺完成: 本次新增 {} 条, 当前端点规则 {} 条",
                inserted, snapshot.size());
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

    /**
     * 由 controller 分包推导能力域; 播种白名单仅 admin / biz 两域 (permitall 链层放行不入表),
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
            case "biz" -> DOMAIN_PORTAL;
            case "third" -> DOMAIN_THIRD;
            default -> null;
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
            rules.add(new Rule(p.getMethod(), p.getPath(), p.getRequiredAuthority(),
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
