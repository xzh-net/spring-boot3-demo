-- ============================================================
-- 合并基线 - IAM 单库 (认证域 + 资源域)
-- 数据库: iam
-- 归属: iam-authorization-server (合并后单服务, 原认证中心 + 资源中心)
-- 表清单 (共 17 表):
--   认证域 5 表: oauth2_authorization_consent / oauth2_authorization_record /
--                oauth2_registered_client / sys_user / iam_external_identity
--   资源域 12 表: sys_permission / sys_role / sys_role_permission / sys_user_role /
--                 sys_scope / sys_scope_permission (客户端授权范围字典, 双维控制客户端维度) /
--                 client_login_policy (登录准入: 客户端×主体 allow-list, 登录维度) /
--                 iam_application / iam_application_channel / iam_org / iam_app_authorization /
--                 iam_endpoint + iam_endpoint_permission (iam_api_capability / iam_capability_subscription 已随开放能力退役删除)
-- 双维准入 (两层解耦):
--   登录层 ①: 能否登录 = client_login_policy 准入表 (allow-list fail-closed);
--             AuthorizeIssuanceFilter 按准入表实时裁决 (已启用), 未命中 302 拒发码 fail-closed。
--   授权层 ②: 令牌业务码 = 用户 RBAC 码 ∩ 客户端 scope 展开码 (自省层交集, fail-closed);
--             iam_client_policy (登录边界策略) 已退役删除, 登录职责移交 client_login_policy。
-- 说明: 租户功能已整体移除 (iam_tenant / iam_tenant_user 表删除, 各表 tenant_code 列、
--       种子值与唯一键中的租户位一并清除)。
-- 基线: iam_identity.sql (原认证中心) + iam_authorization.sql (原资源中心)
-- ============================================================

CREATE DATABASE IF NOT EXISTS iam
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE iam;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ============================================================
-- 认证域 (原 iam_identity, 6 表)
-- ============================================================

-- ----------------------------
-- Table structure for oauth2_authorization_consent
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_authorization_consent`;
CREATE TABLE `oauth2_authorization_consent`  (
  `registered_client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.id)',
  `principal_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '用户名 (主体标识)',
  `authorities` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授予的权限列表 (逗号分隔的 scope, 如 openid,profile)',
  `first_grant_time` datetime(0) NULL DEFAULT NULL COMMENT '首次授权时间 (只在 insert 时写入, 后续 authorities 更新不改动)',
  PRIMARY KEY (`registered_client_id`, `principal_name`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'OAuth2 授权确认表 (用户对客户端的授权同意)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of oauth2_authorization_consent
-- ----------------------------

-- ----------------------------
-- Table structure for oauth2_authorization_record
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_authorization_record`;
CREATE TABLE `oauth2_authorization_record`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `registered_client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.id)',
  `client_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '客户端名称 (冗余字段, 方便查询展示)',
  `principal_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '用户名 (授权主体)',
  `granted_authorities` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授予的权限 (scope 列表, 逗号分隔)',
  `grant_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '授权时间',
  `revoke_time` datetime(0) NULL DEFAULT NULL COMMENT '撤销时间 (status=revoked 时有值)',
  `status` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'active' COMMENT '状态: active=有效, revoked=已撤销',
  `grant_type` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '授权类型: authorization_code / urn:ietf:params:oauth:grant-type:device_code / password 等',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_principal`(`principal_name`) USING BTREE,
  INDEX `idx_client`(`registered_client_id`) USING BTREE,
  INDEX `idx_status`(`status`) USING BTREE,
  INDEX `idx_grant_type`(`grant_type`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'OAuth2 授权记录表 (授权历史日志)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of oauth2_authorization_record
-- ----------------------------

-- ----------------------------
-- Table structure for oauth2_registered_client
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_registered_client`;
CREATE TABLE `oauth2_registered_client`  (
  `id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端主键ID (UUID)',
  `client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端标识符 (对外公开的ID)',
  `client_id_issued_at` datetime(0) NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '客户端ID签发时间',
  `client_secret` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '客户端密钥 (BCrypt 加密), PKCE 客户端可为空',
  `client_secret_expires_at` datetime(0) NULL DEFAULT NULL COMMENT '客户端密钥过期时间 (NULL=永不过期)',
  `client_name` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '客户端名称 (展示用)',
  `client_authentication_methods` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端认证方式: client_secret_basic,client_secret_post,none,private_key_jwt 等',
  `authorization_grant_types` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授权类型: authorization_code,client_credentials,refresh_token,password,urn:ietf:params:oauth:grant-type:device_code',
  `redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '回调地址列表 (逗号分隔)',
  `post_logout_redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '登出后重定向地址 (逗号分隔)',
  `scopes` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授权范围: openid,profile,email 等',
  `client_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端设置 JSON: requireProofKey,requireAuthorizationConsent',
  `token_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '令牌设置 JSON: accessTokenFormat(REFERENCE/SELF_CONTAINED),accessTokenTimeToLive,reuseRefreshTokens,idTokenSignatureAlgorithm',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_client_id`(`client_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'OAuth2 客户端注册表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of oauth2_registered_client
-- ----------------------------
-- INSERT INTO `oauth2_registered_client` VALUES ('1', 'resource-server', '2026-08-13 09:56:12', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '资源服务器', 'client_secret_basic', 'client_credentials', '', '', 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
-- 阶段 4: resource-server 客户端退役 (原跨服务 ServiceTokenProvider/InternalUserDataClient 凭证,
-- 远程调用与 internal 域控制器删除后无消费方; 服务令牌判定改由 grant_type=client_credentials 覆盖)
INSERT INTO `oauth2_registered_client` VALUES ('2', 'admin-app', '2026-08-13 12:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理后台', 'client_secret_basic', 'refresh_token,authorization_code', 'http://localhost:8085/login/oauth2/code/admin-app', 'http://localhost:8001/logged-out', 'openid,profile,admin.full', '{"requireProofKey":true,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT12H"}');
INSERT INTO `oauth2_registered_client` VALUES ('3', 'portal-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '门户应用 (SSO)', 'client_secret_basic', 'refresh_token,authorization_code', 'http://localhost:8084/portal-sso-callback,http://localhost:8081/portal-sso-callback,http://localhost:8080/login/oauth2/code/portal-app-oidc', 'http://localhost:8000/logged-out,http://localhost:8081/logged-out', 'openid,profile,email,portal.profile', '{"requireProofKey":true,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT12H"}');
INSERT INTO `oauth2_registered_client` VALUES ('4', 'oa-web-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, 'OA Web 客户端', 'client_secret_basic', 'authorization_code,refresh_token', 'http://localhost:8081/callback,http://127.0.0.1:8081/callback', 'http://localhost:8081/logout', 'openid,profile,email,third.profile', '{"requireProofKey":true,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT12H","idTokenSignatureAlgorithm":"RS256"}');
INSERT INTO `oauth2_registered_client` VALUES ('5', 'device-app', '2026-08-11 20:00:08', NULL, NULL, '设备客户端', 'none', 'refresh_token,urn:ietf:params:oauth:grant-type:device_code', '', '', 'openid,profile,email', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT1H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT1H"}');
INSERT INTO `oauth2_registered_client` VALUES ('6', 'mobile-app', '2026-08-11 20:00:08', NULL, NULL, '移动原生客户端(PKCE)', 'none', 'refresh_token,authorization_code', 'com.example.mobileapp://oauth2/redirect', NULL, 'openid,profile,email', '{"requireProofKey":true,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT1H"}');
INSERT INTO `oauth2_registered_client` VALUES ('9', 'oa-h5-app', '2026-11-03 12:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, 'OA H5 客户端', 'client_secret_basic', 'authorization_code,refresh_token', 'http://localhost:8084/callback,http://127.0.0.1:8084/callback', 'http://localhost:8084/logout', 'openid,profile,email,third.profile', '{"requireProofKey":true,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"refreshTokenTimeToLive":"PT12H","idTokenSignatureAlgorithm":"RS256"}');
-- INSERT INTO `oauth2_registered_client` VALUES ('7', 'service-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '服务间调用客户端', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
-- 阶段清理: service-app 客户端退役 (client_credentials 演示/测试账号, 无程序特判、无业务消费方;
-- 连带 test.http 第二部分 403 负例与 index.html 展示卡片一并移除)
-- INSERT INTO `oauth2_registered_client` VALUES ('8', 'admin-m2m', '2026-08-16 00:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理 M2M 服务凭证 (认证中心以机器身份执行管理写)', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
-- 阶段清理: admin-m2m 客户端退役 (原删除用户联动清理 M2M 链; 合并单服务后删除链已本地化
-- UserService 直调, 该凭证与 admin-m2m-client-ids 授予白名单均无消费方; V6.9 迁移保留为历史)

-- ----------------------------
-- Table structure for sys_user (凭据主库)
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID (仅内部联表使用, 不下放)',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '业务用户编码 (对外/下放引用, 资源中心与业务应用只认此编码)',
  `username` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '登录用户名',
  `password` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'BCrypt 加密后的密码',
  `nickname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '用户昵称',
  `email` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '电子邮箱',
  `phone` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '手机号码',
  `avatar` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '头像 URL',
  `enabled` tinyint(1) NOT NULL DEFAULT 1 COMMENT '是否启用 (1=启用, 0=禁用)',
  `account_non_expired` tinyint(1) NOT NULL DEFAULT 1 COMMENT '账号是否未过期 (1=未过期, 0=已过期)',
  `account_non_locked` tinyint(1) NOT NULL DEFAULT 1 COMMENT '账号是否未锁定 (1=未锁定, 0=已锁定)',
  `credentials_non_expired` tinyint(1) NOT NULL DEFAULT 1 COMMENT '凭证是否未过期 (1=未过期, 0=已过期)',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `username`(`username`) USING BTREE,
  UNIQUE INDEX `user_code`(`user_code`) USING BTREE,
  INDEX `idx_username`(`username`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '系统用户表 (凭据主库)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES (1, '550e8400-e29b-41d4-a716-446655440001', 'admin', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '管理员', 'admin@example.com', NULL, NULL, 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');
INSERT INTO `sys_user` VALUES (2, '550e8400-e29b-41d4-a716-446655440002', 'user', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '普通用户', 'user@example.com', NULL, NULL, 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');
INSERT INTO `sys_user` VALUES (3, '550e8400-e29b-41d4-a716-446655440003', 'zhangsan', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '张三', 'zhangsan@example.com', NULL, NULL, 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');

-- ----------------------------
-- 退役清理: iam_client_policy (登录边界策略) 已删除, 职责由 scope∧RBAC 双维交集覆盖
-- ----------------------------
DROP TABLE IF EXISTS `iam_client_policy`;

-- ----------------------------
-- Table structure for sys_scope (客户端授权范围字典: 双维控制的客户端维度粗分组, 只读)
-- ----------------------------
DROP TABLE IF EXISTS `sys_scope`;
CREATE TABLE `sys_scope`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'scope 码 (如 admin.full), 客户端注册串 oauth2_registered_client.scopes 引用此码',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '展示名',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用(展开剔除, 持有该组的客户端等同一码不放)',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_code`(`code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '客户端授权范围(scope)字典: 一组权限码的具名粗捆绑 (只读, SQL种子演进)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for sys_scope_permission (scope ↔ 权限码 N:N, 对标 sys_role_permission, 只读)
-- ----------------------------
DROP TABLE IF EXISTS `sys_scope_permission`;
CREATE TABLE `sys_scope_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `scope_id` bigint(0) NOT NULL COMMENT '→ sys_scope.id',
  `permission_id` bigint(0) NOT NULL COMMENT '→ sys_permission.id',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_scope_perm`(`scope_id`, `permission_id`) USING BTREE,
  INDEX `idx_perm`(`permission_id`) USING BTREE,
  CONSTRAINT `fk_scope_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'scope 内含权限码 N:N 映射 (只读, SQL种子演进)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_scope (域信息由 code 前缀表达, 原 domain 列已删;
--   admin.full=admin 全量域码 / portal.profile=门户域码 / third.profile=空映射 fail-closed /
--   openid·profile·email=标准协议 scope (驱动 id_token 与 /userinfo, 无业务映射)
-- remark 约定: 可写谁持有, 不写数量)
-- ----------------------------
INSERT INTO `sys_scope` (id, code, name, status, remark) VALUES
(1, 'admin.full', '管理端全量', 1, '管理后台应用: 全部 admin 域业务码 (admin-app 持有)'),
(2, 'portal.profile', '门户工作台', 1, '门户应用授权范围: 含 portal:client:read (portal-app 持有)'),
(3, 'third.profile', '三方最小集', 1, '三方/外部客户端: 三方域暂无端点, 空映射 fail-closed (oa-web-app / oa-h5-app 持有, 仅 OIDC 标准能力)'),
(4, 'openid', '身份认证', 1, 'OIDC 标准 scope: 签发 id_token 的依据 (各客户端持有)'),
(5, 'profile', '基本资料', 1, 'OIDC 标准 scope: /userinfo 返回昵称/头像 (各客户端持有)'),
(6, 'email', '电子邮箱', 1, 'OIDC 标准 scope: /userinfo 返回邮箱 (除 admin-app 外均持有)');

INSERT INTO `sys_scope_permission` (scope_id, permission_id) VALUES
(1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8),
(1, 9), (1, 10), (1, 11), (1, 12), (1, 13), (1, 14), (1, 15), (1, 16),
(2, 17);

-- ----------------------------
-- Table structure for iam_external_identity (外部身份绑定表: 微信/企业微信/钉钉/支付宝/谷歌/GitHub)
-- ----------------------------
DROP TABLE IF EXISTS `iam_external_identity`;
CREATE TABLE `iam_external_identity`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '本地业务用户编码 (关联 sys_user.user_code)',
  `provider` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '第三方身份提供商: wechat=微信, wecom=企业微信, dingtalk=钉钉, alipay=支付宝, google=谷歌, github=GitHub',
  `provider_open_id` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '第三方唯一标识 (openid/sub/登录标识)',
  `union_id` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方开放平台统一标识 (unionid, 微信系等多端通用; 无则空)',
  `nickname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方昵称 (仅展示, 不覆盖本地昵称)',
  `avatar` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方头像 URL (仅展示, 不覆盖本地头像)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '绑定状态: 1=已绑定有效, 0=已解绑',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '首次绑定时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_provider_open_id`(`provider`, `provider_open_id`) USING BTREE,
  INDEX `idx_user_code`(`user_code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '外部身份绑定表 (第三方身份 ↔ 本地用户)' ROW_FORMAT = Dynamic;

-- ============================================================
-- 资源域 (原 iam_authorization, 11 表; tenant_code 列已移除)
-- ============================================================

-- ----------------------------
-- Table structure for sys_permission
-- ----------------------------
DROP TABLE IF EXISTS `sys_permission`;
CREATE TABLE `sys_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '权限ID',
  `code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限标识 (API 权限码, 如 user:read)',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限名称',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注 (业务分类以前缀标记: 【管理端】/【门户】, 取代原 domain 列)',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `code`(`code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 18 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '权限码字典 (端点绑定见 iam_endpoint_permission, 范围绑定见 sys_scope_permission)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_permission (业务分类由 remark 前缀【管理端】/【门户】标记, 原 domain 列已删; 运行时经用户令牌注入, 端点准入经 iam_endpoint_permission 绑定)
-- ----------------------------
INSERT INTO `sys_permission` (`id`, `code`, `name`, `status`, `remark`) VALUES
(1,  'user:read',         '用户查看',   1, '【管理端】用户列表/详情/用户会话查询'),
(2,  'user:write',        '用户管理',   1, '【管理端】用户增删改/启停/重置密码/踢会话/数据清理'),
(3,  'role:read',         '角色查看',   1, '【管理端】角色列表/用户-角色查询'),
(4,  'role:write',        '角色管理',   1, '【管理端】角色增删改/用户-角色绑定'),
(5,  'session:read',      '会话查看',   1, '【管理端】在线会话/用户会话查询'),
(6,  'session:write',     '会话管理',   1, '【管理端】按会话/在线条目/用户强制下线'),
(7,  'application:read',  '应用查看',   1, '【管理端】应用列表/授权/渠道查询'),
(8,  'application:write', '应用管理',   1, '【管理端】应用增删改/授权配置/渠道增删改'),
(9,  'client:read',       '客户端查看', 1, '【管理端】OAuth2 客户端列表/详情/准入策略查询'),
(10, 'client:write',      '客户端管理', 1, '【管理端】OAuth2 客户端增删改/密钥重置/准入策略配置'),
(11, 'permission:read',   '权限查看',   1, '【管理端】权限码列表'),
(12, 'permission:write',  '权限管理',   1, '【管理端】权限码增删改 (准入引用中的码禁止删除)'),
(13, 'record:read',       '记录查看',   1, '【管理端】授权记录/consent 记录查询'),
(14, 'record:write',      '记录管理',   1, '【管理端】授权记录清空'),
(15, 'policy:read',       '准入查看',   1, '【管理端】资源准入策略 (iam_endpoint) 列表查询'),
(16, 'policy:write',      '准入管理',   1, '【管理端】资源准入策略增删改 (保留码, 写入口已收归自扫描)'),
(17, 'portal:client:read', '门户应用查看', 1, '【门户】门户端「我的应用授权」查询 (/biz/clients/mine)');

-- ----------------------------
-- Table structure for sys_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_role`;
CREATE TABLE `sys_role`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `code` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '角色编码 (如 ADMIN / PORTAL / THIRD_PARTY)',
  `name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '角色名称',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `code`(`code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '角色表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role (内置三角色: ADMIN=管理端 / PORTAL=门户 / THIRD_PARTY=三方)
-- ----------------------------
INSERT INTO `sys_role` VALUES (1, 'ADMIN', '管理员', '管理端运营/运维人员，持有管理 API 权限', '2026-08-13 09:57:52', '2026-08-13 09:57:52');
INSERT INTO `sys_role` VALUES (2, 'PORTAL', '门户用户', '门户端注册用户，持有门户 API 权限', '2026-08-13 09:57:52', '2026-08-13 09:57:52');
INSERT INTO `sys_role` VALUES (3, 'THIRD_PARTY', '三方用户', '第三方/外部接入人员，受限访问', '2026-10-23 09:00:00', '2026-10-23 09:00:00');

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
) ENGINE = InnoDB AUTO_INCREMENT = 15 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '角色-权限关联表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_role_permission (域内自洽: ADMIN 绑 16 个 admin 域码; PORTAL 绑 1 个 portal 域码; THIRD_PARTY 三方域无端点故空)
-- ----------------------------
INSERT INTO `sys_role_permission` VALUES (1, 1, 1);
INSERT INTO `sys_role_permission` VALUES (2, 1, 2);
INSERT INTO `sys_role_permission` VALUES (3, 1, 3);
INSERT INTO `sys_role_permission` VALUES (4, 1, 4);
INSERT INTO `sys_role_permission` VALUES (5, 1, 5);
INSERT INTO `sys_role_permission` VALUES (6, 1, 6);
INSERT INTO `sys_role_permission` VALUES (7, 1, 7);
INSERT INTO `sys_role_permission` VALUES (8, 1, 8);
INSERT INTO `sys_role_permission` VALUES (9, 1, 9);
INSERT INTO `sys_role_permission` VALUES (10, 1, 10);
INSERT INTO `sys_role_permission` VALUES (11, 1, 11);
INSERT INTO `sys_role_permission` VALUES (12, 1, 12);
INSERT INTO `sys_role_permission` VALUES (13, 1, 13);
INSERT INTO `sys_role_permission` VALUES (14, 1, 14);
INSERT INTO `sys_role_permission` VALUES (15, 1, 15);
INSERT INTO `sys_role_permission` VALUES (16, 1, 16);
INSERT INTO `sys_role_permission` VALUES (17, 2, 17);

-- ----------------------------
-- Table structure for sys_user_role (用户-角色关联, 按业务用户编码 user_code)
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '关联ID',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '业务用户编码 (关联 sys_user.user_code)',
  `role_id` bigint(0) NOT NULL COMMENT '角色ID (关联 sys_role.id)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_user_code_role`(`user_code`, `role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '用户-角色关联表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_role
-- ----------------------------
INSERT INTO `sys_user_role` VALUES (1, '550e8400-e29b-41d4-a716-446655440001', 1);
INSERT INTO `sys_user_role` VALUES (2, '550e8400-e29b-41d4-a716-446655440002', 2);
INSERT INTO `sys_user_role` VALUES (3, '550e8400-e29b-41d4-a716-446655440003', 3);

-- ----------------------------
-- Table structure for iam_application (应用表: 门户展示单元)
-- ----------------------------
DROP TABLE IF EXISTS `iam_application`;
CREATE TABLE `iam_application`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '应用ID',
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
  UNIQUE INDEX `app_code`(`app_code`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '应用表 (门户展示单元)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_application (demo: 3 条; 应用授权见 iam_app_authorization)
-- ----------------------------
INSERT INTO `iam_application` VALUES
(1, 'portal', '原生APP',    NULL, 'Android 和 iOS', 1, 0, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 'oa',     'OA 办公系统', NULL, '办公自动化', 2, 0, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 'crm',    '三方终端', NULL, '设备或运行环境不适合直接弹出浏览器、输入账号密码，或者不能安全地保存用户凭证。设备码流把“登录动作”从受限设备转移到用户自己的手机/电脑浏览器上完成，再由受限设备轮询认证结果', 3, 0, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

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
  `sso_client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT 'OAuth2 SSO 客户端 (逻辑引用 oauth2_registered_client.client_id)',
  `secret_status` tinyint(1) NOT NULL DEFAULT 0 COMMENT '密钥状态: 0=未配置, 1=已配置 (仅走UI展示; 密文存客户端表)',
  `client_issued_at` datetime(0) NULL DEFAULT NULL COMMENT '客户端签发时间 (冗余 oauth2_registered_client.client_id_issued_at)',
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
-- Records of iam_application_channel (OA=Web+H5 两形态 / 三方终端=设备码 / 原生APP=占位无URL)
-- ----------------------------
INSERT INTO `iam_application_channel` VALUES
(1, 2, 'WEB',    'Web 门户', 'http://localhost:8081', 'oa-web-app', 0, NULL, 1, 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 2, 'H5',     'H5 门户', 'http://localhost:8084', 'oa-h5-app',  0, NULL, 0, 2, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 3, 'DEVICE', '设备终端', 'http://localhost:8082', 'device-app', 0, NULL, 0, 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(4, 1, 'MOBILE', '原生APP', '',                     'mobile-app', 0, NULL, 0, 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_org (组织表: 应用授权主体之一)
-- ----------------------------
DROP TABLE IF EXISTS `iam_org`;
CREATE TABLE `iam_org`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '组织ID',
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
  INDEX `idx_parent`(`parent_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '组织表 (应用授权主体: ORG=iam_org.org_code)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_org (demo: 集团-公司-部门 两级)
-- ----------------------------
INSERT INTO `iam_org` VALUES
(1, 0, 'HQ',    '集团总部', 'GROUP', 1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 1, 'RND',   '研发部',   'DEPT',  1, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 1, 'SALES', '销售部',   'DEPT',  2, 1, '2026-08-15 10:00:00', '2026-08-15 10:00:00');

-- ----------------------------
-- Table structure for iam_app_authorization (应用授权表)
-- ----------------------------
DROP TABLE IF EXISTS `iam_app_authorization`;
CREATE TABLE `iam_app_authorization`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '授权ID',
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
  UNIQUE INDEX `uk_authz`(`app_id`, `channel_id`, `subject_type`, `subject_id`) USING BTREE,
  INDEX `idx_subject`(`subject_type`, `subject_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '应用授权表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_app_authorization (admin/portal 角色授权三个应用全渠道; ORG/RND 为主体类型样例, ORG 暂不解析)
-- ----------------------------
INSERT INTO `iam_app_authorization` VALUES
(1, 2, 0, 'ROLE', 'ADMIN', 1, '2026-08-15 10:00:00', NULL, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(2, 3, 0, 'ORG',  'RND', 1, '2026-08-15 10:00:00', NULL, '2026-08-15 10:00:00', '2026-08-15 10:00:00'),
(3, 2, 0, 'ROLE', 'PORTAL', 1, '2026-08-17 20:36:16', NULL, '2026-08-17 20:36:16', '2026-08-17 20:36:16'),
(4, 1, 0, 'ROLE', 'ADMIN', 1, '2026-11-03 12:00:00', NULL, '2026-11-03 12:00:00', '2026-11-03 12:00:00'),
(5, 1, 0, 'ROLE', 'PORTAL', 1, '2026-11-03 12:00:00', NULL, '2026-11-03 12:00:00', '2026-11-03 12:00:00'),
(6, 3, 0, 'ROLE', 'ADMIN', 1, '2026-11-03 12:00:00', NULL, '2026-11-03 12:00:00', '2026-11-03 12:00:00'),
(7, 3, 0, 'ROLE', 'PORTAL', 1, '2026-11-03 12:00:00', NULL, '2026-11-03 12:00:00', '2026-11-03 12:00:00');

-- ----------------------------
-- Table structure for client_login_policy (登录准入: 客户端 × 主体 allow-list, 登录维度)
-- 说明: 与授权维度正交 — 本表只裁决①签发准入 (能否登录), 不参与②自省层业务码注入;
--       allow-list fail-closed: 无启用行 = 拒绝所有登录; 不支持 DENY 行。
--       管理 API/页面写入口待评估后补, 当前仅 SQL 种子 (与 iam_endpoint 同为"准入"族)。
-- ----------------------------
DROP TABLE IF EXISTS `client_login_policy`;
CREATE TABLE `client_login_policy`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '准入ID',
  `client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'OAuth2 client_id (逻辑引用 oauth2_registered_client.client_id, 无外键)',
  `subject_type` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '主体类型: ROLE=角色 / USER=用户 / ANY=所有已登录用户',
  `subject_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT '' COMMENT '主体ID: ROLE=sys_role.code / USER=user_code / ANY=空串',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用 (停用行不参与判定)',
  `remark` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_policy`(`client_id`, `subject_type`, `subject_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '客户端登录准入表 (登录维度: 谁能登录该客户端; allow-list, fail-closed)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of client_login_policy (6 行; device-app 收敛为仅 THIRD_PARTY, 其余与原签发准入放行结果一致)
-- ----------------------------
INSERT INTO `client_login_policy` (`client_id`, `subject_type`, `subject_id`, `status`, `remark`) VALUES
('admin-app',   'ROLE', 'ADMIN',  1, '管理后台: 仅 ADMIN 角色 (原交集: ADMIN 16码 ∩ admin.full 16码)'),
('portal-app',  'ROLE', 'PORTAL', 1, '门户 SSO: 仅 PORTAL 角色 (原交集: PORTAL 1码 ∩ portal.profile 1码)'),
('oa-web-app',  'ANY',  '',       1, '三方 Web 演示: 所有登录用户 (原逃逸阀: third.profile 空映射)'),
('oa-h5-app',   'ANY',  '',       1, 'OA H5 演示: 所有登录用户 (原逃逸阀: third.profile 空映射)'),
('device-app',  'ROLE', 'THIRD_PARTY', 1, '设备码客户端: 仅 THIRD_PARTY 角色 (设备/IoT/CLI 三方演示)'),
('mobile-app',  'ANY',  '',       1, '移动原生演示: 所有登录用户 (原逃逸阀: 无业务 scope)');

-- ----------------------------
-- Table structure for iam_endpoint (资源接口准入策略: 资源行, V6.20 拆表)
-- 说明: 资源与绑定分离 —— 本表存资源 (方法/路径/档位/组合语义/状态),
--       PERMISSION 行的具体权限码在 iam_endpoint_permission (1..N, ALL/ANY 组合);
--       档位行 (AUTHENTICATED/PERMIT_ALL) 无绑定。写入 = 种子初始化 + 管理页面维护 (两表同一事务)。
-- ----------------------------
DROP TABLE IF EXISTS `iam_endpoint_permission`;
DROP TABLE IF EXISTS `iam_endpoint`;
CREATE TABLE `iam_endpoint`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '策略ID',
  `method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'HTTP 方法: GET/POST/PUT/DELETE (ANY=全部)',
  `path` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '路径模式 (Spring 注册模式, 如 /admin/permissions/{id})',
  `service_key` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'iam-authorization-server' COMMENT '服务命名空间 (多服务共表预留, 单体阶段固定值)',
  `policy_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'AUTHENTICATED' COMMENT '策略类型: PERMISSION=权限码(见绑定表) / AUTHENTICATED=认证档 / PERMIT_ALL=全放行',
  `permission_logic` varchar(3) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'ALL' COMMENT '组合语义: ALL=全部满足 / ANY=任一满足 (仅 PERMISSION 行有意义)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_endpoint`(`service_key`, `method`, `path`) USING BTREE,
  CONSTRAINT `chk_permission_logic` CHECK (`permission_logic` IN ('ALL', 'ANY'))
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '资源接口准入策略表 (资源行; 写入=种子+页面, 启动只读直查; 权限绑定见 iam_endpoint_permission)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for iam_endpoint_permission (端点↔权限绑定, 1:N)
-- 仅 policy_type=PERMISSION 的资源行产生绑定; endpoint_id CASCADE 删资源自动清绑定;
-- permission_id RESTRICT 被绑定的权限禁删。
-- ----------------------------
CREATE TABLE `iam_endpoint_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '绑定ID',
  `endpoint_id` bigint(0) NOT NULL COMMENT '→ iam_endpoint.id (资源行)',
  `permission_id` bigint(0) NOT NULL COMMENT '→ sys_permission.id (所需权限码)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_endpoint_permission`(`endpoint_id`, `permission_id`) USING BTREE,
  CONSTRAINT `fk_ee_endpoint` FOREIGN KEY (`endpoint_id`) REFERENCES `iam_endpoint` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `fk_ee_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '端点↔权限绑定 (PERMISSION 行使用, 一端点多权限 1:N, ALL/ANY 组合)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_endpoint (56 行: 51 条业务端点 + 3 条本表写接口 + 2 条范围映射写接口)
-- 写入语义: 种子一次性初始化 + 管理页面维护, 上线后以库数据为准; 规则每请求直查 DB。
-- 种子全为 PERMISSION 行 → 后置 UPDATE 定型 (若未来加入档位行种子, 此句需同步调整)。
-- ----------------------------
INSERT INTO `iam_endpoint` (`method`, `path`, `status`) VALUES
('GET', '/admin/users', 1),
('GET', '/admin/users/{id}', 1),
('GET', '/admin/users/{id}/sessions', 1),
('POST', '/admin/users', 1),
('PUT', '/admin/users/{id}', 1),
('DELETE', '/admin/users/{id}', 1),
('PUT', '/admin/users/{id}/enable', 1),
('POST', '/admin/users/{id}/reset-password', 1),
('DELETE', '/admin/users/{id}/sessions', 1),
('DELETE', '/admin/users/{userCode}/data', 1),
('GET', '/admin/roles', 1),
('GET', '/admin/user-roles/{userCode}', 1),
('POST', '/admin/roles', 1),
('PUT', '/admin/roles/{id}', 1),
('DELETE', '/admin/roles/{id}', 1),
('PUT', '/admin/user-roles/{userCode}', 1),
('GET', '/admin/sessions/online', 1),
('GET', '/admin/sessions/users/{id}', 1),
('POST', '/admin/sessions/{ssoSessionId}/logout', 1),
('DELETE', '/admin/sessions/online/{username}', 1),
('POST', '/admin/sessions/users/{id}/logout', 1),
('GET', '/admin/applications', 1),
('GET', '/admin/applications/{appId}/authorizations', 1),
('GET', '/admin/applications/{appId}/channels', 1),
('POST', '/admin/applications', 1),
('PUT', '/admin/applications/{id}', 1),
('DELETE', '/admin/applications/{id}', 1),
('POST', '/admin/applications/authorizations', 1),
('DELETE', '/admin/applications/authorizations/{id}', 1),
('POST', '/admin/applications/{appId}/channels', 1),
('PUT', '/admin/applications/{appId}/channels/{channelId}', 1),
('DELETE', '/admin/applications/{appId}/channels/{channelId}', 1),
('GET', '/admin/clients', 1),
('GET', '/admin/clients/{id}', 1),
('GET', '/admin/scopes', 1),
('POST', '/admin/clients', 1),
('PUT', '/admin/clients/{id}', 1),
('DELETE', '/admin/clients/{id}', 1),
('POST', '/admin/clients/{id}/reset-secret', 1),
('GET', '/admin/login-policies', 1),
('GET', '/admin/login-policies/{clientId}', 1),
('PUT', '/admin/login-policies/{clientId}', 1),
('GET', '/admin/permissions', 1),
('POST', '/admin/permissions', 1),
('PUT', '/admin/permissions/{id}', 1),
('DELETE', '/admin/permissions/{id}', 1),
('GET', '/admin/records', 1),
('GET', '/admin/records/consents', 1),
('DELETE', '/admin/records', 1),
('GET', '/admin/endpoint-policies', 1),
('POST', '/admin/endpoint-policies', 1),
('PUT', '/admin/endpoint-policies/{id}', 1),
('DELETE', '/admin/endpoint-policies/{id}', 1),
('POST', '/admin/permissions/{id}/scopes/{scopeId}', 1),
('DELETE', '/admin/permissions/{id}/scopes/{scopeId}', 1),
('GET', '/biz/clients/mine', 1);

UPDATE `iam_endpoint` SET `policy_type` = 'PERMISSION' WHERE `policy_type` = 'AUTHENTICATED';

-- ----------------------------
-- Records of iam_endpoint_permission (与资源行按 (method,path,code) 三元组回填)
-- ----------------------------
INSERT INTO `iam_endpoint_permission` (`endpoint_id`, `permission_id`)
SELECT `e`.`id`, `p`.`id`
  FROM `iam_endpoint` `e`
  JOIN (
    SELECT 'GET' AS `m`, '/admin/users' AS `pa`, 'user:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/users/{id}' AS `pa`, 'user:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/users/{id}/sessions' AS `pa`, 'user:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/users' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/users/{id}' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/users/{id}' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/users/{id}/enable' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/users/{id}/reset-password' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/users/{id}/sessions' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/users/{userCode}/data' AS `pa`, 'user:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/roles' AS `pa`, 'role:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/user-roles/{userCode}' AS `pa`, 'role:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/roles' AS `pa`, 'role:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/roles/{id}' AS `pa`, 'role:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/roles/{id}' AS `pa`, 'role:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/user-roles/{userCode}' AS `pa`, 'role:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/sessions/online' AS `pa`, 'session:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/sessions/users/{id}' AS `pa`, 'session:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/sessions/{ssoSessionId}/logout' AS `pa`, 'session:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/sessions/online/{username}' AS `pa`, 'session:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/sessions/users/{id}/logout' AS `pa`, 'session:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/applications' AS `pa`, 'application:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/applications/{appId}/authorizations' AS `pa`, 'application:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/applications/{appId}/channels' AS `pa`, 'application:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/applications' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/applications/{id}' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/applications/{id}' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/applications/authorizations' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/applications/authorizations/{id}' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/applications/{appId}/channels' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/applications/{appId}/channels/{channelId}' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/applications/{appId}/channels/{channelId}' AS `pa`, 'application:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/clients' AS `pa`, 'client:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/clients/{id}' AS `pa`, 'client:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/scopes' AS `pa`, 'client:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/clients' AS `pa`, 'client:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/clients/{id}' AS `pa`, 'client:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/clients/{id}' AS `pa`, 'client:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/clients/{id}/reset-secret' AS `pa`, 'client:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/login-policies' AS `pa`, 'client:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/login-policies/{clientId}' AS `pa`, 'client:read' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/login-policies/{clientId}' AS `pa`, 'client:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/permissions' AS `pa`, 'permission:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/permissions' AS `pa`, 'permission:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/permissions/{id}' AS `pa`, 'permission:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/permissions/{id}' AS `pa`, 'permission:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/records' AS `pa`, 'record:read' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/records/consents' AS `pa`, 'record:read' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/records' AS `pa`, 'record:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/admin/endpoint-policies' AS `pa`, 'policy:read' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/endpoint-policies' AS `pa`, 'policy:write' AS `code` UNION ALL
    SELECT 'PUT' AS `m`, '/admin/endpoint-policies/{id}' AS `pa`, 'policy:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/endpoint-policies/{id}' AS `pa`, 'policy:write' AS `code` UNION ALL
    SELECT 'POST' AS `m`, '/admin/permissions/{id}/scopes/{scopeId}' AS `pa`, 'permission:write' AS `code` UNION ALL
    SELECT 'DELETE' AS `m`, '/admin/permissions/{id}/scopes/{scopeId}' AS `pa`, 'permission:write' AS `code` UNION ALL
    SELECT 'GET' AS `m`, '/biz/clients/mine' AS `pa`, 'portal:client:read' AS `code`
  ) `t` ON `t`.`m` = `e`.`method` AND `t`.`pa` = `e`.`path`
  JOIN `sys_permission` `p` ON `p`.`code` = `t`.`code`;
-- ===================== 阶段清理: 开放能力体系退役 =====================
-- iam_api_capability / iam_capability_subscription 两表及种子已退役 (CAPABILITY 订阅机制清理,
-- 本期权限架构改造决定不保留 client×能力订阅粒度); 历史迁移 V6.5 保留为记录, 新库不再建这两表。
-- 原内容 (L409-465) 见 git 历史 / V6.5 迁移脚本。
-- ====================================================================
-- -- ----------------------------
-- -- Table structure for iam_api_capability (开放能力登记表)
-- -- ----------------------------
-- DROP TABLE IF EXISTS `iam_api_capability`;
-- CREATE TABLE `iam_api_capability`  (
--   `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '能力ID',
--   `capability_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力编码 (业务唯一, 如 contact:query)',
--   `capability_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力名称',
--   `method` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'HTTP 方法',
--   `path_pattern` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '路径模式 (Ant 风格, 如 /api/capability/contacts/{id})',
--   `required_scopes` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '令牌所需 scope (逗号分隔, 空=不限制)',
--   `owner` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '归属 (产品线/部门)',
--   `qps_limit` int(0) NOT NULL DEFAULT 0 COMMENT '全局 QPS 上限 (0=不限制; 仅登记断言, 限流计数另表)',
--   `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用',
--   `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
--   `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
--   `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
--   PRIMARY KEY (`id`) USING BTREE,
--   UNIQUE INDEX `uk_capability_code`(`capability_code`) USING BTREE,
--   UNIQUE INDEX `uk_capability_route`(`method`, `path_pattern`) USING BTREE
-- ) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力登记表 (暴露给开发者的 API 能力)' ROW_FORMAT = Dynamic;
-- 
-- -- ----------------------------
-- -- Records of iam_api_capability (demo: 通讯录能力 2 条, 与 controller/capability 端点对应)
-- -- ----------------------------
-- INSERT INTO `iam_api_capability` VALUES
-- (1, 'contact:query', '通讯录列表', 'GET', '/api/capability/contacts', 'read', '研发部', 0, 1, '通讯录列表查询能力', '2026-08-16 10:00:00', '2026-08-16 10:00:00'),
-- (2, 'contact:detail', '通讯录详情', 'GET', '/api/capability/contacts/{id}', 'read', '研发部', 0, 1, '通讯录单条详情查询能力', '2026-08-16 10:00:00', '2026-08-16 10:00:00');
-- 
-- -- ----------------------------
-- -- Table structure for iam_capability_subscription (开放能力订阅表: 开发者客户端 × 能力)
-- -- ----------------------------
-- DROP TABLE IF EXISTS `iam_capability_subscription`;
-- CREATE TABLE `iam_capability_subscription`  (
--   `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '订阅ID',
--   `client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '订阅方客户端 (oauth2_registered_client.client_id, 逻辑引用, 非FK)',
--   `capability_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '能力编码 (逻辑引用 iam_api_capability.capability_code)',
--   `env` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'PROD' COMMENT '环境: PROD=生产/TEST=测试',
--   `qps_limit` int(0) NOT NULL DEFAULT 0 COMMENT '订阅 QPS 上限 (0=不限制)',
--   `quota_daily` int(0) NOT NULL DEFAULT 0 COMMENT '每日调用次数上限 (0=不限制)',
--   `quota_monthly` int(0) NOT NULL DEFAULT 0 COMMENT '每月调用次数上限 (0=不限制)',
--   `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=订阅中, 0=已取消',
--   `subscribe_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '订阅时间',
--   `expire_time` datetime(0) NULL DEFAULT NULL COMMENT '到期时间 (NULL=长期有效)',
--   `revoke_time` datetime(0) NULL DEFAULT NULL COMMENT '取消时间',
--   `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
--   `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
--   PRIMARY KEY (`id`) USING BTREE,
--   UNIQUE INDEX `uk_subscription`(`client_id`, `capability_code`, `env`) USING BTREE
-- ) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '开放能力订阅表 (开发者客户端 × 能力)' ROW_FORMAT = Dynamic;
-- 
-- -- ----------------------------
-- -- Records of iam_capability_subscription (demo: 移动端客户端订阅通讯录两项能力)
-- -- ----------------------------
-- INSERT INTO `iam_capability_subscription` VALUES
-- (1, 'mobile-app', 'contact:query', 'PROD', 100, 100000, 3000000, 1, '2026-08-16 10:00:00', NULL, NULL, '2026-08-16 10:00:00', '2026-08-16 10:00:00'),
-- (2, 'mobile-app', 'contact:detail', 'PROD', 100, 100000, 3000000, 1, '2026-08-16 10:00:00', NULL, NULL, '2026-08-16 10:00:00', '2026-08-16 10:00:00');

SET FOREIGN_KEY_CHECKS = 1;
