package net.xzh.iam.open.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import net.xzh.iam.open.entity.IamApiCapability;
import net.xzh.iam.open.entity.IamCapabilitySubscription;
import net.xzh.iam.open.mapper.IamApiCapabilityMapper;
import net.xzh.iam.open.mapper.IamCapabilitySubscriptionMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 开放能力服务 (iam_api_capability + iam_capability_subscription).
 * <p>
 * 能力准入 (scheme B): /api/capability/** 专属引擎 — 匹配能力路由 → 校验 scope → 校验
 * 客户端订阅 (status=1 且在有效期内)。未登记能力按拒绝处理 (登记制)。
 * qps/quota 本期仅登记断言, 实际限流计数另表 (二期)。
 * </p>
 */
@Slf4j
@Service
public class CapabilityService {

    /** 默认环境 (订阅/准入按此环境匹配) */
    public static final String ENV = "PROD";

    private final IamApiCapabilityMapper capabilityMapper;
    private final IamCapabilitySubscriptionMapper subscriptionMapper;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 能力路由快照 (volatile: 管理端变更后刷新) */
    private volatile List<CapabilityRoute> routes = List.of();

    /** 订阅快照 (volatile) */
    private volatile List<IamCapabilitySubscription> subscriptions = List.of();

    public CapabilityService(IamApiCapabilityMapper capabilityMapper,
                             IamCapabilitySubscriptionMapper subscriptionMapper) {
        this.capabilityMapper = capabilityMapper;
        this.subscriptionMapper = subscriptionMapper;
    }

    /** 能力路由快照条目 */
    public record CapabilityRoute(String capabilityCode, String method, String pathPattern) {
    }

    /** 能力准入裁决结果 */
    public enum Admission {
        ALLOWED, NOT_REGISTERED, DISABLED, SCOPE_DENIED, NO_SUBSCRIPTION
    }

    // ==================== 能力登记 ====================

    public List<IamApiCapability> listCapabilities() {
        return capabilityMapper.selectList(
                new QueryWrapper<IamApiCapability>().orderByAsc("capability_code"));
    }

    public IamApiCapability getCapability(Long id) {
        return capabilityMapper.selectById(id);
    }

    @Transactional
    public void createCapability(IamApiCapability capability) {
        validateCapability(capability, null);
        capability.setTenantCode("T001");
        capability.setStatus(capability.getStatus() == null ? 1 : capability.getStatus());
        capabilityMapper.insert(capability);
        reloadSnapshots();
    }

    @Transactional
    public void updateCapability(Long id, IamApiCapability capability) {
        validateCapability(capability, id);
        IamApiCapability exist = capabilityMapper.selectById(id);
        if (exist == null) {
            throw new IllegalArgumentException("能力不存在: " + id);
        }
        exist.setCapabilityName(capability.getCapabilityName());
        exist.setMethod(capability.getMethod());
        exist.setPathPattern(capability.getPathPattern());
        exist.setRequiredScopes(capability.getRequiredScopes());
        exist.setOwner(capability.getOwner());
        exist.setQpsLimit(capability.getQpsLimit() == null ? 0 : capability.getQpsLimit());
        exist.setStatus(capability.getStatus() == null ? 1 : capability.getStatus());
        exist.setRemark(capability.getRemark());
        capabilityMapper.updateById(exist);
        reloadSnapshots();
    }

    @Transactional
    public void deleteCapability(Long id) {
        capabilityMapper.deleteById(id);
        reloadSnapshots();
    }

    private void validateCapability(IamApiCapability capability, Long selfId) {
        if (!StringUtils.hasText(capability.getCapabilityCode())) {
            throw new IllegalArgumentException("能力编码不能为空");
        }
        if (!StringUtils.hasText(capability.getMethod())) {
            throw new IllegalArgumentException("HTTP 方法不能为空");
        }
        if (!StringUtils.hasText(capability.getPathPattern())) {
            throw new IllegalArgumentException("路径模式不能为空");
        }
        boolean dupCode = capabilityMapper.selectList(new QueryWrapper<IamApiCapability>()
                        .ne(selfId != null, "id", selfId)
                        .eq("tenant_code", "T001")
                        .eq("capability_code", capability.getCapabilityCode()))
                .size() > 0;
        if (dupCode) {
            throw new IllegalArgumentException("能力编码已存在: " + capability.getCapabilityCode());
        }
        boolean dupRoute = capabilityMapper.selectList(new QueryWrapper<IamApiCapability>()
                        .ne(selfId != null, "id", selfId)
                        .eq("method", capability.getMethod())
                        .eq("path_pattern", capability.getPathPattern()))
                .size() > 0;
        if (dupRoute) {
            throw new IllegalArgumentException("能力路由已存在: " + capability.getMethod() + " " + capability.getPathPattern());
        }
    }

    // ==================== 能力订阅 ====================

    public List<IamCapabilitySubscription> listSubscriptions(String capabilityCode, String clientId) {
        QueryWrapper<IamCapabilitySubscription> qw = new QueryWrapper<>();
        qw.orderByAsc("capability_code", "client_id");
        if (StringUtils.hasText(capabilityCode)) {
            qw.eq("capability_code", capabilityCode);
        }
        if (StringUtils.hasText(clientId)) {
            qw.eq("client_id", clientId);
        }
        return subscriptionMapper.selectList(qw);
    }

    @Transactional
    public void createSubscription(IamCapabilitySubscription sub) {
        if (!StringUtils.hasText(sub.getClientId())) {
            throw new IllegalArgumentException("订阅方 client_id 不能为空");
        }
        if (!StringUtils.hasText(sub.getCapabilityCode())) {
            throw new IllegalArgumentException("能力编码不能为空");
        }
        if (subscriptionMapper.selectCount(new QueryWrapper<IamCapabilitySubscription>()
                .eq("tenant_code", "T001")
                .eq("client_id", sub.getClientId())
                .eq("capability_code", sub.getCapabilityCode())
                .eq("env", ENV)) > 0) {
            throw new IllegalArgumentException("订阅已存在: " + sub.getClientId() + " × " + sub.getCapabilityCode());
        }
        sub.setTenantCode("T001");
        sub.setEnv(ENV);
        sub.setStatus(1);
        sub.setSubscribeTime(LocalDateTime.now());
        sub.setQpsLimit(sub.getQpsLimit() == null ? 0 : sub.getQpsLimit());
        sub.setQuotaDaily(sub.getQuotaDaily() == null ? 0 : sub.getQuotaDaily());
        sub.setQuotaMonthly(sub.getQuotaMonthly() == null ? 0 : sub.getQuotaMonthly());
        subscriptionMapper.insert(sub);
        reloadSnapshots();
    }

    @Transactional
    public void updateSubscription(Long id, IamCapabilitySubscription sub) {
        IamCapabilitySubscription exist = subscriptionMapper.selectById(id);
        if (exist == null) {
            throw new IllegalArgumentException("订阅不存在: " + id);
        }
        exist.setQpsLimit(sub.getQpsLimit() == null ? 0 : sub.getQpsLimit());
        exist.setQuotaDaily(sub.getQuotaDaily() == null ? 0 : sub.getQuotaDaily());
        exist.setQuotaMonthly(sub.getQuotaMonthly() == null ? 0 : sub.getQuotaMonthly());
        exist.setExpireTime(sub.getExpireTime());
        subscriptionMapper.updateById(exist);
        reloadSnapshots();
    }

    /** 取消订阅: 置 status=0 + revoke_time, 不物理删除 */
    @Transactional
    public void revokeSubscription(Long id) {
        IamCapabilitySubscription exist = subscriptionMapper.selectById(id);
        if (exist == null) {
            throw new IllegalArgumentException("订阅不存在: " + id);
        }
        exist.setStatus(0);
        exist.setRevokeTime(LocalDateTime.now());
        subscriptionMapper.updateById(exist);
        reloadSnapshots();
    }

    // ==================== 准入裁决 ====================

    /**
     * 能力准入: 匹配路由 → scope → 客户端订阅。
     *
     * @param attributes 令牌属性 (client_id / aud 用于判定订阅方)
     * @param scopes     令牌 scope
     */
    public Admission admit(String httpMethod, String requestUri, Map<String, Object> attributes, Collection<String> scopes) {
        CapabilityRoute route = findCapability(httpMethod, requestUri);
        if (route == null) {
            return Admission.NOT_REGISTERED;
        }
        IamApiCapability capability = capabilityMapper.selectOne(
                new QueryWrapper<IamApiCapability>().eq("capability_code", route.capabilityCode()));
        if (capability == null || capability.getStatus() == null || capability.getStatus() != 1) {
            return Admission.DISABLED;
        }
        if (StringUtils.hasText(capability.getRequiredScopes())) {
            Set<String> required = Set.of(capability.getRequiredScopes().split(","));
            if (!scopes.containsAll(required)) {
                return Admission.SCOPE_DENIED;
            }
        }
        String clientId = resolveClientId(attributes);
        if (!StringUtils.hasText(clientId)) {
            return Admission.NO_SUBSCRIPTION;
        }
        boolean subscribed = subscriptions.stream().anyMatch(s ->
                s.getStatus() != null && s.getStatus() == 1
                        && ENV.equals(s.getEnv())
                        && clientId.equals(s.getClientId())
                        && route.capabilityCode().equals(s.getCapabilityCode())
                        && (s.getExpireTime() == null || s.getExpireTime().isAfter(LocalDateTime.now())));
        return subscribed ? Admission.ALLOWED : Admission.NO_SUBSCRIPTION;
    }

    /** 匹配能力路由 (Ant 风格, 优先更具体的路径) */
    private CapabilityRoute findCapability(String httpMethod, String requestUri) {
        return routes.stream()
                .filter(r -> (r.method().equalsIgnoreCase(httpMethod)
                        || r.method().equalsIgnoreCase("ANY"))
                        && pathMatcher.match(r.pathPattern(), requestUri))
                .max(Comparator.comparingInt((CapabilityRoute r) -> r.pathPattern().length()))
                .orElse(null);
    }

    private String resolveClientId(Map<String, Object> attributes) {
        Object clientId = attributes.get("client_id");
        if (clientId != null) {
            return clientId.toString();
        }
        Object aud = attributes.get("aud");
        if (aud instanceof Collection<?> list && !list.isEmpty()) {
            return String.valueOf(list.iterator().next());
        }
        return aud == null ? null : aud.toString();
    }

    private synchronized void reloadSnapshots() {
        routes = capabilityMapper.selectList(new QueryWrapper<IamApiCapability>())
                .stream()
                .map(c -> new CapabilityRoute(c.getCapabilityCode(), c.getMethod(), c.getPathPattern()))
                .toList();
        subscriptions = List.copyOf(subscriptionMapper.selectList(
                new QueryWrapper<IamCapabilitySubscription>().eq("status", 1)));
    }
}