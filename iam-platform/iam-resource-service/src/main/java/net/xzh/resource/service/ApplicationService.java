package net.xzh.resource.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.resource.entity.IamAppAuthorization;
import net.xzh.resource.entity.IamApplication;
import net.xzh.resource.entity.IamApplicationChannel;
import net.xzh.resource.entity.IamOrg;
import net.xzh.resource.mapper.IamAppAuthorizationMapper;
import net.xzh.resource.mapper.IamApplicationChannelMapper;
import net.xzh.resource.mapper.IamApplicationMapper;
import net.xzh.resource.mapper.IamOrgMapper;
import net.xzh.resource.mapper.SysRoleMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 应用管理服务 (iam_authorization 应用域).
 * <p>管理 iam_application / iam_application_channel / iam_app_authorization 三张表,
 * 承载门户工作台的应用目录 (方案 A: 渠道挂 sso_client_id, 密钥零落库)。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApplicationService {

    private final IamApplicationMapper applicationMapper;
    private final IamApplicationChannelMapper channelMapper;
    private final IamAppAuthorizationMapper authorizationMapper;
    private final IamOrgMapper orgMapper;
    private final SysRoleMapper roleMapper;

    // ==================== 应用 ====================

    public List<Map<String, Object>> listApplications() {
        return applicationMapper.selectList(
                        new QueryWrapper<IamApplication>().orderByAsc("sort", "id"))
                .stream().map(this::toAppMap).toList();
    }

    private Map<String, Object> toAppMap(IamApplication app) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", app.getId());
        item.put("tenantCode", app.getTenantCode());
        item.put("appCode", app.getAppCode());
        item.put("appName", app.getAppName());
        item.put("icon", app.getIcon());
        item.put("description", app.getDescription());
        item.put("sort", app.getSort());
        item.put("visible", app.getVisible());
        item.put("status", app.getStatus());
        item.put("createTime", app.getCreateTime());
        item.put("updateTime", app.getUpdateTime());
        item.put("channels", listChannels(app.getId()));
        return item;
    }

    public IamApplication getApplication(Long id) {
        return applicationMapper.selectById(id);
    }

    @Transactional
    public void createApplication(IamApplication app) {
        if (!StringUtils.hasText(app.getAppCode())) {
            throw new IllegalArgumentException("应用编码不能为空");
        }
        if (applicationMapper.selectCount(
                new QueryWrapper<IamApplication>().eq("app_code", app.getAppCode())) > 0) {
            throw new IllegalArgumentException("应用编码已存在: " + app.getAppCode());
        }
        if (!StringUtils.hasText(app.getTenantCode())) app.setTenantCode("T001");
        if (app.getSort() == null) app.setSort(0);
        if (app.getVisible() == null) app.setVisible(1);
        if (app.getStatus() == null) app.setStatus(1);
        app.setCreateTime(LocalDateTime.now());
        app.setUpdateTime(app.getCreateTime());
        applicationMapper.insert(app);
        log.info("新增应用 appCode={}", app.getAppCode());
    }

    @Transactional
    public void updateApplication(Long id, IamApplication app) {
        IamApplication existing = applicationMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("应用不存在: " + id);
        if (StringUtils.hasText(app.getAppName())) existing.setAppName(app.getAppName());
        if (app.getIcon() != null) existing.setIcon(app.getIcon());
        if (app.getDescription() != null) existing.setDescription(app.getDescription());
        if (app.getSort() != null) existing.setSort(app.getSort());
        if (app.getVisible() != null) existing.setVisible(app.getVisible());
        if (app.getStatus() != null) existing.setStatus(app.getStatus());
        existing.setUpdateTime(LocalDateTime.now());
        applicationMapper.updateById(existing);
        log.info("更新应用 id={}, appCode={}", id, existing.getAppCode());
    }

    @Transactional
    public void deleteApplication(Long id) {
        IamApplication app = applicationMapper.selectById(id);
        if (app == null) throw new IllegalArgumentException("应用不存在: " + id);
        channelMapper.delete(new QueryWrapper<IamApplicationChannel>().eq("app_id", id));
        authorizationMapper.delete(new QueryWrapper<IamAppAuthorization>().eq("app_id", id));
        applicationMapper.deleteById(id);
        log.info("删除应用 id={}, appCode={}", id, app.getAppCode());
    }

    // ==================== 渠道 ====================

    public List<IamApplicationChannel> listChannels(Long appId) {
        return channelMapper.selectList(
                new QueryWrapper<IamApplicationChannel>()
                        .eq("app_id", appId).orderByAsc("sort", "id"));
    }

    @Transactional
    public void createChannel(Long appId, IamApplicationChannel channel) {
        if (applicationMapper.selectById(appId) == null) {
            throw new IllegalArgumentException("应用不存在: " + appId);
        }
        if (!StringUtils.hasText(channel.getChannelName())) {
            throw new IllegalArgumentException("渠道名称不能为空");
        }
        channel.setAppId(appId);
        if (!StringUtils.hasText(channel.getChannelType())) channel.setChannelType("WEB");
        if (channel.getSecretStatus() == null) channel.setSecretStatus(0);
        if (channel.getIsDefault() == null) channel.setIsDefault(0);
        if (channel.getSort() == null) channel.setSort(0);
        if (channel.getStatus() == null) channel.setStatus(1);
        channel.setCreateTime(LocalDateTime.now());
        channel.setUpdateTime(channel.getCreateTime());
        channelMapper.insert(channel);
        log.info("新增渠道 appId={}, channelName={}", appId, channel.getChannelName());
    }

    @Transactional
    public void updateChannel(Long appId, Long channelId, IamApplicationChannel channel) {
        IamApplicationChannel existing = channelMapper.selectById(channelId);
        if (existing == null) throw new IllegalArgumentException("渠道不存在: " + channelId);
        if (StringUtils.hasText(channel.getChannelName())) existing.setChannelName(channel.getChannelName());
        if (StringUtils.hasText(channel.getChannelType())) existing.setChannelType(channel.getChannelType());
        if (channel.getAccessUrl() != null) existing.setAccessUrl(channel.getAccessUrl());
        if (channel.getSsoClientId() != null) existing.setSsoClientId(channel.getSsoClientId());
        if (channel.getSecretStatus() != null) existing.setSecretStatus(channel.getSecretStatus());
        if (channel.getClientIssuedAt() != null) existing.setClientIssuedAt(channel.getClientIssuedAt());
        if (channel.getIsDefault() != null) existing.setIsDefault(channel.getIsDefault());
        if (channel.getSort() != null) existing.setSort(channel.getSort());
        if (channel.getStatus() != null) existing.setStatus(channel.getStatus());
        existing.setUpdateTime(LocalDateTime.now());
        channelMapper.updateById(existing);
        log.info("更新渠道 id={}, appId={}", channelId, appId);
    }

    @Transactional
    public void deleteChannel(Long appId, Long channelId) {
        IamApplicationChannel channel = channelMapper.selectById(channelId);
        if (channel == null) throw new IllegalArgumentException("渠道不存在: " + channelId);
        authorizationMapper.delete(new QueryWrapper<IamAppAuthorization>()
                .eq("app_id", appId).eq("channel_id", channelId));
        channelMapper.deleteById(channelId);
        log.info("删除渠道 id={}, appId={}", channelId, appId);
    }

    // ==================== 应用授权 ====================

    public List<IamAppAuthorization> listAuthorizations(Long appId) {
        return authorizationMapper.selectList(
                new QueryWrapper<IamAppAuthorization>().eq("app_id", appId).orderByAsc("id"));
    }

    @Transactional
    public void createAuthorization(IamAppAuthorization authorization) {
        if (authorization.getAppId() == null || applicationMapper.selectById(authorization.getAppId()) == null) {
            throw new IllegalArgumentException("应用不存在");
        }
        if (!StringUtils.hasText(authorization.getTenantCode())) authorization.setTenantCode("T001");
        if (authorization.getChannelId() == null) authorization.setChannelId(0L);
        if (!StringUtils.hasText(authorization.getSubjectType())) {
            throw new IllegalArgumentException("授权主体类型不能为空");
        }
        if (!StringUtils.hasText(authorization.getSubjectId())) {
            throw new IllegalArgumentException("授权主体 ID 不能为空");
        }
        if ("ROLE".equalsIgnoreCase(authorization.getSubjectType())) {
            if (roleMapper.selectCount(new QueryWrapper<net.xzh.resource.entity.SysRole>()
                    .eq("code", authorization.getSubjectId())) == 0) {
                throw new IllegalArgumentException("角色编码不存在: " + authorization.getSubjectId());
            }
        }
        if ("ORG".equalsIgnoreCase(authorization.getSubjectType())) {
            if (orgMapper.selectCount(new QueryWrapper<IamOrg>()
                    .eq("org_code", authorization.getSubjectId())) == 0) {
                throw new IllegalArgumentException("组织编码不存在: " + authorization.getSubjectId());
            }
        }
        long exists = authorizationMapper.selectCount(new QueryWrapper<IamAppAuthorization>()
                .eq("tenant_code", authorization.getTenantCode())
                .eq("app_id", authorization.getAppId())
                .eq("channel_id", authorization.getChannelId())
                .eq("subject_type", authorization.getSubjectType())
                .eq("subject_id", authorization.getSubjectId()));
        if (exists > 0) {
            throw new IllegalArgumentException("该授权已存在");
        }
        if (authorization.getStatus() == null) authorization.setStatus(1);
        authorization.setGrantTime(LocalDateTime.now());
        authorization.setCreateTime(authorization.getGrantTime());
        authorization.setUpdateTime(authorization.getGrantTime());
        authorizationMapper.insert(authorization);
        log.info("新增应用授权 appId={}, subjectType={}, subjectId={}",
                authorization.getAppId(), authorization.getSubjectType(), authorization.getSubjectId());
    }

    @Transactional
    public void deleteAuthorization(Long id) {
        IamAppAuthorization authorization = authorizationMapper.selectById(id);
        if (authorization == null) throw new IllegalArgumentException("授权不存在: " + id);
        authorizationMapper.deleteById(id);
        log.info("删除应用授权 id={}", id);
    }

    /**
     * 删除某用户 (USER 主体) 的全部应用授权 (认证中心删除 sys_user 时联动清理).
     *
     * @return 删除条数
     */
    @Transactional
    public int deleteUserAuthorizations(String userCode) {
        int deleted = authorizationMapper.delete(new QueryWrapper<IamAppAuthorization>()
                .eq("subject_type", "USER")
                .eq("subject_id", userCode));
        if (deleted > 0) {
            log.info("删除用户应用授权 userCode={}, count={}", userCode, deleted);
        }
        return deleted;
    }

    // ==================== 门户: 当前人员可见客户端 ====================

    /**
     * 查询当前人员可见的应用/渠道客户端列表 (门户应用卡片, 方案: 应用授权过滤).
     * <p>规则:
     * <ul>
     *   <li>仅返回启用 (status=1) 的应用与其启用渠道;</li>
     *   <li>{@code visible=1} (全部可见) → 用户可直接看到全部启用渠道;</li>
     *   <li>{@code visible=0} (仅授权可见) → 需有有效授权 (status=1): 主体为当前用户
     *       (USER=user_code) 或当前用户任一角色 (ROLE=角色编码 sys_role.code); 授权 channel_id=0
     *       表示全渠道, &gt;0 仅该渠道;</li>
     *   <li>ORG 主体暂不解析 (用户→组织归属映射未实现, 见设计文档 §9 待补)。</li>
     * </ul>
     */
    public List<Map<String, Object>> listVisibleClients(String userCode, List<String> roleCodes) {
        List<IamApplication> apps = applicationMapper.selectList(
                new QueryWrapper<IamApplication>().eq("status", 1).orderByAsc("sort", "id"));
        List<IamAppAuthorization> authzList = authorizationMapper.selectList(
                new QueryWrapper<IamAppAuthorization>().eq("status", 1));
        Map<Long, List<IamAppAuthorization>> authzByApp = authzList.stream()
                .collect(Collectors.groupingBy(IamAppAuthorization::getAppId));

        List<Map<String, Object>> result = new ArrayList<>();
        for (IamApplication app : apps) {
            boolean visibleAll = app.getVisible() != null && app.getVisible() == 1;
            List<IamApplicationChannel> channels = listChannels(app.getId());
            if (visibleAll) {
                for (IamApplicationChannel ch : channels) {
                    if (Integer.valueOf(1).equals(ch.getStatus())) {
                        result.add(toClientCard(app, ch));
                    }
                }
                continue;
            }
            boolean appLevel = false;
            Set<Long> channelIds = new HashSet<>();
            for (IamAppAuthorization authz : authzByApp.getOrDefault(app.getId(), List.of())) {
                if (!matchesSubject(authz, userCode, roleCodes)) continue;
                if (authz.getChannelId() == null || authz.getChannelId() == 0) {
                    appLevel = true;
                } else {
                    channelIds.add(authz.getChannelId());
                }
            }
            for (IamApplicationChannel ch : channels) {
                if (!Integer.valueOf(1).equals(ch.getStatus())) continue;
                if (appLevel || channelIds.contains(ch.getId())) {
                    result.add(toClientCard(app, ch));
                }
            }
        }
        return result;
    }

    /** 授权主体匹配: USER=user_code / ROLE=角色编码 sys_role.code / ORG=组织编码 (暂不解析) */
    private boolean matchesSubject(IamAppAuthorization authz, String userCode, List<String> roleCodes) {
        if ("USER".equalsIgnoreCase(authz.getSubjectType())) {
            return userCode != null && userCode.equals(authz.getSubjectId());
        }
        if ("ROLE".equalsIgnoreCase(authz.getSubjectType())) {
            return roleCodes != null && roleCodes.contains(authz.getSubjectId());
        }
        return false;
    }

    /** 门户卡片结构: 应用 + 渠道 (与前端 SSO 跳转卡片对齐) */
    private Map<String, Object> toClientCard(IamApplication app, IamApplicationChannel ch) {
        Map<String, Object> card = new LinkedHashMap<>();
        card.put("appId", app.getId());
        card.put("appCode", app.getAppCode());
        card.put("name", app.getAppName());
        card.put("icon", app.getIcon());
        card.put("description", app.getDescription());
        card.put("sort", app.getSort());
        card.put("channelId", ch.getId());
        card.put("channelName", ch.getChannelName());
        card.put("type", ch.getChannelType());
        card.put("clientId", ch.getSsoClientId());
        card.put("ssoUrl", ch.getAccessUrl());
        card.put("isDefault", ch.getIsDefault());
        return card;
    }
}
