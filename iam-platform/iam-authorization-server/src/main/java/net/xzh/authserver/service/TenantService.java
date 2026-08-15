package net.xzh.authserver.service;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.xzh.authserver.entity.Tenant;
import net.xzh.authserver.entity.TenantUser;
import net.xzh.authserver.mapper.TenantMapper;
import net.xzh.authserver.mapper.TenantUserMapper;

/**
 * 租户管理服务 (iam_identity.iam_tenant + iam_tenant_user).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TenantService {

    private final TenantMapper tenantMapper;
    private final TenantUserMapper tenantUserMapper;

    public List<Tenant> list() {
        return tenantMapper.selectList(new QueryWrapper<Tenant>().orderByAsc("id"));
    }

    public Tenant get(Long id) {
        return tenantMapper.selectById(id);
    }

    @Transactional
    public void create(Tenant tenant) {
        if (!StringUtils.hasText(tenant.getTenantCode())) {
            throw new IllegalArgumentException("租户编码不能为空");
        }
        if (tenantMapper.selectCount(new QueryWrapper<Tenant>().eq("tenant_code", tenant.getTenantCode())) > 0) {
            throw new IllegalArgumentException("租户编码已存在: " + tenant.getTenantCode());
        }
        if (tenant.getStatus() == null) tenant.setStatus(true);
        tenant.setCreateTime(LocalDateTime.now());
        tenant.setUpdateTime(tenant.getCreateTime());
        tenantMapper.insert(tenant);
        log.info("新增租户 tenantCode={}", tenant.getTenantCode());
    }

    @Transactional
    public void update(Long id, Tenant tenant) {
        Tenant existing = tenantMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("租户不存在: " + id);
        if (StringUtils.hasText(tenant.getTenantName())) existing.setTenantName(tenant.getTenantName());
        if (tenant.getStatus() != null) existing.setStatus(tenant.getStatus());
        existing.setUpdateTime(LocalDateTime.now());
        tenantMapper.updateById(existing);
        log.info("更新租户 id={}", id);
    }

    @Transactional
    public void delete(Long id) {
        Tenant existing = tenantMapper.selectById(id);
        if (existing == null) throw new IllegalArgumentException("租户不存在: " + id);
        tenantMapper.deleteById(id);
        tenantUserMapper.delete(new QueryWrapper<TenantUser>().eq("tenant_id", id));
        log.info("删除租户 id={}, tenantCode={}", id, existing.getTenantCode());
    }

    public List<Tenant> listTenantsOfUser(Long userId) {
        return tenantUserMapper.selectTenantsOfUser(userId);
    }

    /**
     * 覆盖式保存用户-租户绑定 (整体替换).
     */
    @Transactional
    public void assignTenantsToUser(Long userId, List<Long> tenantIds) {
        tenantUserMapper.delete(new QueryWrapper<TenantUser>().eq("user_id", userId));
        if (tenantIds == null) return;
        for (Long tenantId : tenantIds) {
            if (tenantId == null) continue;
            TenantUser tu = new TenantUser();
            tu.setTenantId(tenantId);
            tu.setUserId(userId);
            tu.setStatus(true);
            tenantUserMapper.insert(tu);
        }
        log.info("为用户 userId={} 绑定租户 tenantIds={}", userId, tenantIds);
    }
}
