package net.xzh.resource.config;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * 开放能力体系建表 + 种子初始化器 (幂等).
 * <p>
 * 落地 V6.5 三张表 (iam_endpoint_policy / iam_api_capability / iam_capability_subscription) 于
 * 存量库 (新库由 iam_authorization.sql 直接建), 并幂等补种 demo 能力 2 条 + 订阅 2 条。
 * 仅负责 schema 与登记数据, endpoint_policy 的准入点行由 {@link EndpointPolicyScanInitializer}
 * 启动扫描播种。
 * </p>
 */
@Slf4j
@Order(2)
@Component
public class CapabilitySchemaInitializer implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public CapabilitySchemaInitializer(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            createEndpointPolicyTable();
            createApiCapabilityTable();
            createCapabilitySubscriptionTable();
            seedCapabilities();
            seedSubscriptions();
            log.info("[CapabilitySchema] V6.5 表结构与种子数据就绪");
        } catch (Exception e) {
            log.error("[CapabilitySchema] 初始化失败: {}", e.getMessage(), e);
        }
    }

    private void createEndpointPolicyTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS `iam_endpoint_policy` (
                  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '策略ID',
                  `domain` varchar(20) NOT NULL COMMENT '能力域: admin=管理端/portal=门户/capability=开放能力/internal=服务间内部/permitall=放行(公开)/other=其他',
                  `method` varchar(10) NOT NULL COMMENT 'HTTP 方法: GET/POST/PUT/DELETE (ANY=全部)',
                  `path` varchar(255) NOT NULL COMMENT '路径模式 (Spring 注册模式, 如 /api/admin/permissions/{id})',
                  `required_authority` varchar(100) NOT NULL DEFAULT 'AUTHENTICATED' COMMENT '准入要求: PERMIT_ALL/AUTHENTICATED/ADMIN_SERVICE_TOKEN 管理服务凭证/PORTAL_SERVICE_TOKEN 门户服务凭证/CAPABILITY=按开放能力订阅校验',
                  `source` varchar(10) NOT NULL DEFAULT 'coded' COMMENT '来源: coded=启动扫描默认/override=管理端覆盖',
                  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
                  `remark` varchar(500) DEFAULT NULL COMMENT '备注',
                  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_endpoint` (`method`, `path`),
                  KEY `idx_domain` (`domain`)
                ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '资源接口准入策略表 (启动扫描播种, 管理端覆盖)'
                """);
    }

    private void createApiCapabilityTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS `iam_api_capability` (
                  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '能力ID',
                  `tenant_code` varchar(64) NOT NULL COMMENT '租户编码 (逻辑引用 iam_tenant.tenant_code, 非FK)',
                  `capability_code` varchar(64) NOT NULL COMMENT '能力编码 (业务唯一, 如 contact:query)',
                  `capability_name` varchar(100) NOT NULL COMMENT '能力名称',
                  `method` varchar(10) NOT NULL COMMENT 'HTTP 方法',
                  `path_pattern` varchar(255) NOT NULL COMMENT '路径模式 (Ant 风格, 如 /api/capability/contacts/{id})',
                  `required_scopes` varchar(255) DEFAULT NULL COMMENT '令牌所需 scope (逗号分隔, 空=不限制)',
                  `owner` varchar(64) DEFAULT NULL COMMENT '归属 (产品线/部门)',
                  `qps_limit` int NOT NULL DEFAULT 0 COMMENT '全局 QPS 上限 (0=不限制; 限流计数另表)',
                  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用',
                  `remark` varchar(500) DEFAULT NULL,
                  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_capability_code` (`tenant_code`, `capability_code`),
                  UNIQUE KEY `uk_capability_route` (`method`, `path_pattern`)
                ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力登记表 (暴露给开发者的 API 能力)'
                """);
    }

    private void createCapabilitySubscriptionTable() {
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS `iam_capability_subscription` (
                  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '订阅ID',
                  `tenant_code` varchar(64) NOT NULL COMMENT '租户编码 (逻辑引用 iam_tenant.tenant_code, 非FK)',
                  `client_id` varchar(128) NOT NULL COMMENT '订阅方客户端 (oauth2_registered_client.client_id, 逻辑引用, 非FK)',
                  `capability_code` varchar(64) NOT NULL COMMENT '能力编码 (逻辑引用 iam_api_capability.capability_code)',
                  `env` varchar(20) NOT NULL DEFAULT 'PROD' COMMENT '环境: PROD=生产/TEST=测试',
                  `qps_limit` int NOT NULL DEFAULT 0 COMMENT '订阅 QPS 上限 (0=不限制)',
                  `quota_daily` int NOT NULL DEFAULT 0 COMMENT '每日调用次数上限 (0=不限制)',
                  `quota_monthly` int NOT NULL DEFAULT 0 COMMENT '每月调用次数上限 (0=不限制)',
                  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=订阅中, 0=已取消',
                  `subscribe_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `expire_time` datetime DEFAULT NULL COMMENT '到期时间 (NULL=长期有效)',
                  `revoke_time` datetime DEFAULT NULL,
                  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
                  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                  PRIMARY KEY (`id`),
                  UNIQUE KEY `uk_subscription` (`tenant_code`, `client_id`, `capability_code`, `env`)
                ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力订阅表 (开发者客户端 × 能力)'
                """);
    }

    private void seedCapabilities() {
        int seeded = jdbcTemplate.update("""
                INSERT INTO `iam_api_capability`
                    (`tenant_code`, `capability_code`, `capability_name`, `method`, `path_pattern`, `required_scopes`, `owner`, `qps_limit`, `status`, `remark`)
                SELECT 'T001', 'contact:query',  '通讯录列表', 'GET', '/api/capability/contacts',       'read', '研发部', 0, 1, '通讯录列表查询能力'
                WHERE NOT EXISTS (SELECT 1 FROM `iam_api_capability` WHERE capability_code = 'contact:query')
                """);
        seeded += jdbcTemplate.update("""
                INSERT INTO `iam_api_capability`
                    (`tenant_code`, `capability_code`, `capability_name`, `method`, `path_pattern`, `required_scopes`, `owner`, `qps_limit`, `status`, `remark`)
                SELECT 'T001', 'contact:detail', '通讯录详情', 'GET', '/api/capability/contacts/{id}', 'read', '研发部', 0, 1, '通讯录单条详情查询能力'
                WHERE NOT EXISTS (SELECT 1 FROM `iam_api_capability` WHERE capability_code = 'contact:detail')
                """);
        if (seeded > 0) {
            log.info("[CapabilitySchema] 补种开放能力 {} 条", seeded);
        }
    }

    private void seedSubscriptions() {
        int seeded = jdbcTemplate.update("""
                INSERT INTO `iam_capability_subscription`
                    (`tenant_code`, `client_id`, `capability_code`, `env`, `qps_limit`, `quota_daily`, `quota_monthly`, `status`)
                SELECT 'T001', 'mobile-app', 'contact:query', 'PROD', 100, 100000, 3000000, 1
                WHERE NOT EXISTS (SELECT 1 FROM `iam_capability_subscription`
                                  WHERE client_id = 'mobile-app' AND capability_code = 'contact:query' AND env = 'PROD')
                """);
        seeded += jdbcTemplate.update("""
                INSERT INTO `iam_capability_subscription`
                    (`tenant_code`, `client_id`, `capability_code`, `env`, `qps_limit`, `quota_daily`, `quota_monthly`, `status`)
                SELECT 'T001', 'mobile-app', 'contact:detail', 'PROD', 100, 100000, 3000000, 1
                WHERE NOT EXISTS (SELECT 1 FROM `iam_capability_subscription`
                                  WHERE client_id = 'mobile-app' AND capability_code = 'contact:detail' AND env = 'PROD')
                """);
        if (seeded > 0) {
            log.info("[CapabilitySchema] 补种能力订阅 {} 条", seeded);
        }
    }
}