-- ============================================================
-- V6.5 数据库拆分 - 资源中心业务库 (业务 RBAC + 应用域 + 组织, 无影子用户表)
-- 数据库: iam_authorization
-- 归属: iam-resource-service
-- 表清单: sys_role / sys_permission / sys_role_permission / sys_user_role
--         iam_application / iam_application_channel / iam_app_authorization / iam_org
--         iam_endpoint_policy / iam_api_capability / iam_capability_subscription  (共 11 表)
-- 说明: 用户身份权威在认证中心 iam_identity.sys_user; 资源中心以业务用户编码
--       user_code (token sub) 直接关联 sys_user_role → sys_role, 不再维护影子用户表。
--       应用域 3 表承载门户工作台的应用目录 (方案 A: 渠道挂 sso_client_id, 密钥零落库)。
-- 基线: oauth2_server 单体库 (RBAC 部分结构保持一致) + 应用数据模型设计 V1.5
-- ============================================================

CREATE DATABASE IF NOT EXISTS iam_authorization
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE iam_authorization;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for sys_permission
-- ----------------------------
DROP TABLE IF EXISTS `sys_permission`;
CREATE TABLE `sys_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '权限ID',
  `code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限标识 (如 app:crm)',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限名称',
  `type` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'app' COMMENT '权限类型: app=应用访问',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `code`(`code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '权限表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_permission
-- ----------------------------
INSERT INTO `sys_permission` VALUES (1, 'app:portal', '门户应用', 'app', '统一工作台门户', '2026-08-13 09:57:52');
INSERT INTO `sys_permission` VALUES (2, 'app:oa', 'OA 办公系统', 'app', '办公自动化', '2026-08-13 09:57:52');
INSERT INTO `sys_permission` VALUES (3, 'app:crm', 'CRM 客户管理', 'app', '客户关系管理', '2026-08-13 09:57:52');
INSERT INTO `sys_permission` VALUES (4, 'app:erp', 'ERP 企业资源', 'app', '企业资源计划', '2026-08-13 09:57:52');
INSERT INTO `sys_permission` VALUES (5, 'app:bi', 'BI 数据分析', 'app', '商业智能分析', '2026-08-13 09:57:52');

-- ----------------------------
-- Table structure for sys_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `code` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '角色编码 (如 ADMIN / USER)',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '角色名称',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `code`(`code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '角色表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role
-- ----------------------------
INSERT INTO `sys_role` VALUES (1, 'ADMIN', '管理员', '拥有全部应用访问权限', '2026-08-13 09:57:52', '2026-08-13 09:57:52');
INSERT INTO `sys_role` VALUES (2, 'USER', '普通用户', '仅可访问门户与 OA', '2026-08-13 09:57:52', '2026-08-13 09:57:52');

-- ----------------------------
-- Table structure for sys_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `sys_role_permission`;
CREATE TABLE `sys_role_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '关联ID',
  `role_id` bigint(0) NOT NULL COMMENT '角色ID (关联 sys_role.id)',
  `permission_id` bigint(0) NOT NULL COMMENT '权限ID (关联 sys_permission.id)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_role_permission`(`role_id`, `permission_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 8 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '角色-权限关联表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role_permission
-- ----------------------------
INSERT INTO `sys_role_permission` VALUES (1, 1, 1);
INSERT INTO `sys_role_permission` VALUES (2, 1, 2);
INSERT INTO `sys_role_permission` VALUES (3, 1, 3);
INSERT INTO `sys_role_permission` VALUES (4, 1, 4);
INSERT INTO `sys_role_permission` VALUES (5, 1, 5);
INSERT INTO `sys_role_permission` VALUES (6, 2, 1);
INSERT INTO `sys_role_permission` VALUES (7, 2, 2);

-- ----------------------------
-- Table structure for sys_user_role (用户-角色关联, 按业务用户编码 user_code)
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '关联ID',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '业务用户编码 (关联 iam_identity.sys_user.user_code)',
  `role_id` bigint(0) NOT NULL COMMENT '角色ID (关联 sys_role.id)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_user_code_role`(`user_code`, `role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '用户-角色关联表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_role
-- ----------------------------
INSERT INTO `sys_user_role` VALUES (1, 'u_1a2b3c4d5e6f708090a0b0c0d0e0f001', 1);
INSERT INTO `sys_user_role` VALUES (2, 'u_1a2b3c4d5e6f708090a0b0c0d0e0f002', 2);

-- ----------------------------
-- Table structure for iam_application (应用表: 门户展示单元)
-- ----------------------------
DROP TABLE IF EXISTS `iam_application`;
CREATE TABLE `iam_application`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '应用ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK, 下放用编码)',
  `app_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '应用编码 (业务唯一, 如 OA)',
  `app_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '应用名称',
  `icon` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '应用图标 URL',
  `description` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '应用描述',
  `sort` int(0) NOT NULL DEFAULT 0 COMMENT '门户排序 (小前大后)',
  `visible` tinyint(1) NOT NULL DEFAULT 1 COMMENT '门户可见性: 1=全部可见(无需授权), 0=仅授权可见',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `app_code`(`app_code`) USING BTREE,
  INDEX `idx_tenant`(`tenant_code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '应用表 (门户展示单元)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_application (demo: 3 条, 与 sys_permission app:portal/app:oa/app:crm 对齐)
-- ----------------------------
INSERT INTO `iam_application` VALUES
(1, 'T001', 'portal', '门户工作台', NULL, '统一工作台门户', 1, 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 'T001', 'oa',     'OA 办公系统', NULL, '办公自动化', 2, 0, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 'T001', 'crm',    'CRM 客户管理', NULL, '客户关系管理', 3, 0, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_application_channel (渠道表: 应用 1:N 门户形态 + SSO 客户端绑定)
-- ----------------------------
DROP TABLE IF EXISTS `iam_application_channel`;
CREATE TABLE `iam_application_channel`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '渠道ID',
  `app_id` bigint(0) NOT NULL COMMENT '应用ID (关联 iam_application.id)',
  `channel_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '渠道形态: WEB=Web门户, MOBILE=移动门户 (可扩展 H5/MINI)',
  `channel_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '渠道名称',
  `access_url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '跳转地址 (Web/移动端各自地址)',
  `sso_client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT 'OAuth2 SSO 客户端 (逻辑引用认证中心 oauth2_registered_client.client_id)',
  `secret_status` tinyint(1) NOT NULL DEFAULT 0 COMMENT '密钥状态: 0=未配置, 1=已配置 (仅走UI展示; 密文存认证中心)',
  `client_issued_at` datetime(0) NULL DEFAULT NULL COMMENT '客户端签发时间 (冗余认证中心 client_id_issued_at)',
  `is_default` tinyint(1) NOT NULL DEFAULT 0 COMMENT '默认渠道: 1=是 (同应用仅一个), 0=否',
  `sort` int(0) NOT NULL DEFAULT 0 COMMENT '排序',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_sso_client`(`sso_client_id`) USING BTREE,
  INDEX `idx_app`(`app_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '应用渠道表 (门户形态 + SSO 客户端绑定)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_application_channel (demo: OA 应用 Web + 移动两种形态)
-- ----------------------------
INSERT INTO `iam_application_channel` VALUES
(1, 2, 'WEB',    'Web 门户', 'http://localhost:8081', NULL, 0, NULL, 1, 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 2, 'MOBILE', '移动门户', 'http://localhost:8082', NULL, 0, NULL, 0, 2, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_org (组织表: 应用授权主体之一)
-- ----------------------------
DROP TABLE IF EXISTS `iam_org`;
CREATE TABLE `iam_org`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '组织ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK, 下放用编码)',
  `parent_id` bigint(0) NOT NULL DEFAULT 0 COMMENT '父组织ID: 0=根组织',
  `org_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '组织编码 (业务唯一, 如 RND)',
  `org_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '组织名称',
  `org_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'DEPT' COMMENT '组织类型: GROUP=集团/COMPANY=公司/DEPT=部门',
  `sort` int(0) NOT NULL DEFAULT 0 COMMENT '排序 (小前大后)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_org_code`(`org_code`) USING BTREE,
  INDEX `idx_parent`(`parent_id`) USING BTREE,
  INDEX `idx_tenant`(`tenant_code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '组织表 (应用授权主体: ORG=iam_org.org_code)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_org (demo: 集团-公司-部门 两级)
-- ----------------------------
INSERT INTO `iam_org` VALUES
(1, 'T001', 0, 'HQ',    '集团总部', 'GROUP', 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 'T001', 1, 'RND',   '研发部',   'DEPT',  1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 'T001', 1, 'SALES', '销售部',   'DEPT',  2, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_app_authorization (应用授权表)
-- ----------------------------
DROP TABLE IF EXISTS `iam_app_authorization`;
CREATE TABLE `iam_app_authorization`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '授权ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (逻辑引用认证中心 iam_tenant.tenant_code, 非FK)',
  `app_id` bigint(0) NOT NULL COMMENT '应用ID (关联 iam_application.id)',
  `channel_id` bigint(0) NOT NULL DEFAULT 0 COMMENT '渠道ID: 0=整个应用全渠道, >0=仅该渠道',
  `subject_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授权主体类型: ROLE=角色/USER=用户/ORG=组织',
  `subject_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授权主体ID (ROLE=角色编码 sys_role.code; USER=业务用户编码 user_code; ORG=组织编码 iam_org.org_code)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=有效, 0=停用',
  `grant_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '授权时间',
  `revoke_time` datetime(0) NULL DEFAULT NULL COMMENT '撤销时间',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_authz`(`tenant_code`, `app_id`, `channel_id`, `subject_type`, `subject_id`) USING BTREE,
  INDEX `idx_subject`(`subject_type`, `subject_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '应用授权表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_app_authorization (demo: 管理员角色授权 OA 全渠道; 研发部授权 CRM, 主体按编码)
-- ----------------------------
INSERT INTO `iam_app_authorization` VALUES
(1, 'T001', 2, 0, 'ROLE', 'ADMIN', 1, '2026-08-15 10:00:00', NULL, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 'T001', 3, 0, 'ORG',  'RND', 1, '2026-08-15 10:00:00', NULL, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_endpoint_policy (资源接口准入策略: 启动扫描播种 + 管理端覆盖)
-- 说明: 数据行由 iam-resource-service 启动时按 controller 分包扫描 RequestMapping 自动播种
--       (source=coded 默认规则), 管理端可覆盖为 override; 未登记路径按默认拒绝 (deny-by-default)。
-- ----------------------------
DROP TABLE IF EXISTS `iam_endpoint_policy`;
CREATE TABLE `iam_endpoint_policy`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '策略ID',
  `domain` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力域: admin=管理端/portal=门户/capability=开放能力/internal=服务间内部/permitall=放行(公开)/other=其他',
  `method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'HTTP 方法: GET/POST/PUT/DELETE (ANY=全部)',
  `path` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '路径模式 (Spring 注册模式, 如 /api/admin/permissions/{id})',
  `required_authority` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'AUTHENTICATED' COMMENT '准入要求: PERMIT_ALL=放行/AUTHENTICATED=任意凭证/ADMIN_SERVICE_TOKEN=管理服务凭证/PORTAL_SERVICE_TOKEN=门户服务凭证/CAPABILITY=按开放能力订阅校验',
  `source` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'coded' COMMENT '来源: coded=启动扫描默认/override=管理端覆盖',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_endpoint`(`method`, `path`) USING BTREE,
  INDEX `idx_domain`(`domain`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '资源接口准入策略表 (启动扫描播种, 管理端覆盖)' ROW_FORMAT = Dynamic;

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