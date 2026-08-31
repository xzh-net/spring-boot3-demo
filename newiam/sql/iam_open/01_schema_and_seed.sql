-- ============================================================
-- newiam V2 形态 - 开放平台库 (能力目录 + 订阅)
-- 数据库: iam_open
-- 归属: iam-open-service (本库唯一写者)
-- 表清单: iam_api_capability / iam_capability_subscription  (共 2 表)
-- 说明: 自 iam_authorization 迁入 (开放能力种子归位开放平台)。
--       能力目录表本身即开放平台的 API 准入登记表 (登记制, 未登记默认拒绝),
--       订阅表维护 client_id × capability 的商业关系。token 签发复用认证中心。
-- ============================================================

CREATE DATABASE IF NOT EXISTS iam_open
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE iam_open;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
-- ----------------------------
-- Table structure for iam_api_capability (开放能力登记表)
-- ----------------------------
DROP TABLE IF EXISTS `iam_api_capability`;
CREATE TABLE `iam_api_capability`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '能力ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK)',
  `capability_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力编码 (业务唯一, 如 contact:query)',
  `capability_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力名称',
  `method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'HTTP 方法',
  `path_pattern` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '路径模式 (Ant 风格, 如 /api/capability/contacts/{id})',
  `required_scopes` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '令牌所需 scope (逗号分隔, 空=不限制)',
  `owner` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '归属 (产品线/部门)',
  `qps_limit` int(0) NOT NULL DEFAULT 0 COMMENT '全局 QPS 上限 (0=不限制; 仅登记断言, 限流计数另表)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_capability_code`(`tenant_code`, `capability_code`) USING BTREE,
  UNIQUE INDEX `uk_capability_route`(`method`, `path_pattern`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力登记表 (暴露给开发者的 API 能力)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_api_capability (demo: 通讯录能力 2 条, 与 controller/capability 端点对应)
-- ----------------------------
INSERT INTO `iam_api_capability` VALUES
(1, 'T001', 'contact:query', '通讯录列表', 'GET', '/api/capability/contacts', 'read', '研发部', 0, 1, '通讯录列表查询能力', '2026-08-16 10:00:00', '2026-08-16 10:00:00'),
(2, 'T001', 'contact:detail', '通讯录详情', 'GET', '/api/capability/contacts/{id}', 'read', '研发部', 0, 1, '通讯录单条详情查询能力', '2026-08-16 10:00:00', '2026-08-16 10:00:00');

-- ----------------------------
-- Table structure for iam_capability_subscription (开放能力订阅表: 开发者客户端 × 能力)
-- ----------------------------
DROP TABLE IF EXISTS `iam_capability_subscription`;
CREATE TABLE `iam_capability_subscription`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '订阅ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK)',
  `client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '订阅方客户端 (oauth2_registered_client.client_id, 逻辑引用, 非FK)',
  `capability_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力编码 (逻辑引用 iam_api_capability.capability_code)',
  `env` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'PROD' COMMENT '环境: PROD=生产/TEST=测试',
  `qps_limit` int(0) NOT NULL DEFAULT 0 COMMENT '订阅 QPS 上限 (0=不限制)',
  `quota_daily` int(0) NOT NULL DEFAULT 0 COMMENT '每日调用次数上限 (0=不限制)',
  `quota_monthly` int(0) NOT NULL DEFAULT 0 COMMENT '每月调用次数上限 (0=不限制)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=订阅中, 0=已取消',
  `subscribe_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '订阅时间',
  `expire_time` datetime(0) NULL DEFAULT NULL COMMENT '到期时间 (NULL=长期有效)',
  `revoke_time` datetime(0) NULL DEFAULT NULL COMMENT '取消时间',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_subscription`(`tenant_code`, `client_id`, `capability_code`, `env`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力订阅表 (开发者客户端 × 能力)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_capability_subscription (demo: 移动端客户端订阅通讯录两项能力)
-- ----------------------------
INSERT INTO `iam_capability_subscription` VALUES
(1, 'T001', 'mobile-app', 'contact:query', 'PROD', 100, 100000, 3000000, 1, '2026-08-16 10:00:00', NULL, NULL, '2026-08-16 10:00:00', '2026-08-16 10:00:00'),
(2, 'T001', 'mobile-app', 'contact:detail', 'PROD', 100, 100000, 3000000, 1, '2026-08-16 10:00:00', NULL, NULL, '2026-08-16 10:00:00', '2026-08-16 10:00:00');

SET FOREIGN_KEY_CHECKS = 1;
