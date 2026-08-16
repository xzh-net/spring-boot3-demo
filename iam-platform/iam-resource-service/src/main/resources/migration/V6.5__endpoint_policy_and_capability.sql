-- V6.5 迁移 - 资源中心准入策略 + 开放能力体系 (iam_endpoint_policy / iam_api_capability / iam_capability_subscription)
-- 背景: 资源接口准入由 yaml/代码写死 4 条规则演进为「启动扫描播种 + 管理端覆盖」的表驱动;
--       开放能力登记 + 开发者客户端订阅 (scheme B: /api/capability/** 命名空间与 endpoint_policy 分流, 两表互不读对方主表)。
--       令牌类别命名: 管理令牌 MANAGEMENT_TOKEN / 服务令牌 SERVICE_TOKEN (v6.5.x 由 ROLE_ADMIN/ROLE_SERVICE 更名,
--       后续版本统一不再产生 ROLE_ 前缀的令牌类别 authority; V6.6 起更名为 ADMIN_SERVICE_TOKEN / PORTAL_SERVICE_TOKEN)。
-- 实际建表/种子由 CapabilitySchemaInitializer + EndpointPolicyScanInitializer (ApplicationRunner) 幂等执行,
-- 本脚本仅供参考/审计。新库 (iam_authorization.sql V6.5) 已含三表与 demo, 无需执行;
-- 存量库只需执行一次下述四段即可 (后续由初始化器保证幂等)。

USE iam_authorization;

-- ============ 1. iam_endpoint_policy ============
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
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '资源接口准入策略表 (启动扫描播种, 管理端覆盖)';

-- 行数据由启动扫描自动播种 (按 controller 分包 + RequestMapping 推导默认规则), 不在此手填。

-- ============ 2. iam_api_capability ============
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
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力登记表 (暴露给开发者的 API 能力)';

INSERT IGNORE INTO `iam_api_capability` (`tenant_code`, `capability_code`, `capability_name`, `method`, `path_pattern`, `required_scopes`, `owner`, `qps_limit`, `status`, `remark`) VALUES
('T001', 'contact:query',  '通讯录列表', 'GET', '/api/capability/contacts',       'read', '研发部', 0, 1, '通讯录列表查询能力'),
('T001', 'contact:detail', '通讯录详情', 'GET', '/api/capability/contacts/{id}', 'read', '研发部', 0, 1, '通讯录单条详情查询能力');

-- ============ 3. iam_capability_subscription ============
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
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力订阅表 (开发者客户端 × 能力)';

INSERT IGNORE INTO `iam_capability_subscription`
(`tenant_code`, `client_id`, `capability_code`, `env`, `qps_limit`, `quota_daily`, `quota_monthly`, `status`) VALUES
('T001', 'mobile-app', 'contact:query',  'PROD', 100, 100000, 3000000, 1),
('T001', 'mobile-app', 'contact:detail', 'PROD', 100, 100000, 3000000, 1);

-- ============ 4. 令牌类别改名迁移 (幂等) ============
-- 背景: 令牌类别由 ROLE_ADMIN/ROLE_SERVICE (存业务角色码 + 外部拼 ROLE_ 前缀) 统一更名为
--       MANAGEMENT_TOKEN (管理令牌) / SERVICE_TOKEN (服务令牌), 后续不再产生 ROLE_ 前缀令牌类别。
-- 存量 iam_endpoint_policy 行按旧值刷成新值; 新库由扫描初始化器直接播种新值, 无需执行。
UPDATE `iam_endpoint_policy` SET `required_authority` = 'MANAGEMENT_TOKEN', `remark` = IFNULL(`remark`, '') WHERE `required_authority` = 'ROLE_ADMIN';
UPDATE `iam_endpoint_policy` SET `required_authority` = 'SERVICE_TOKEN', `remark` = IFNULL(`remark`, '') WHERE `required_authority` = 'ROLE_SERVICE';