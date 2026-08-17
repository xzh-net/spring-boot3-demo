-- ============================================================
-- V5 数据库拆分 - 认证中心主库 (凭据主库)
-- 数据库: iam_identity
-- 归属: iam-authorization-server (全量 IdP)
-- 表清单: oauth2_authorization_consent / oauth2_authorization_record /
--         oauth2_registered_client / sys_user  (共 4 表)
-- 说明: sys_user 为用户凭据主库 (用户名/密码哈希/账号状态),
--       认证中心本地校验, 登录零远程凭据调用.
-- 基线: oauth2_server 单体库 (结构保持一致)
-- ============================================================

CREATE DATABASE IF NOT EXISTS iam_identity
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE iam_identity;

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

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
  `scopes` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '授权范围: openid,profile,email,read,write',
  `client_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端设置 JSON: requireProofKey,requireAuthorizationConsent',
  `token_settings` varchar(2000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '令牌设置 JSON: accessTokenFormat(REFERENCE/SELF_CONTAINED),accessTokenTimeToLive,reuseRefreshTokens,idTokenSignatureAlgorithm',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_client_id`(`client_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'OAuth2 客户端注册表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of oauth2_registered_client
-- ----------------------------
INSERT INTO `oauth2_registered_client` VALUES ('1', 'resource-server', '2026-08-13 09:56:12', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '资源服务器', 'client_secret_basic', 'client_credentials', '', '', 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
INSERT INTO `oauth2_registered_client` VALUES ('2', 'admin-app', '2026-08-13 12:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理后台', 'client_secret_basic', 'refresh_token,authorization_code', 'http://localhost:8085/login/oauth2/code/admin-app', 'http://localhost:8001/logged-out', 'openid,profile,read,write', '{"requireProofKey":false,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":true}');
INSERT INTO `oauth2_registered_client` VALUES ('3', 'portal-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '门户应用 (SSO)', 'client_secret_basic', 'refresh_token,authorization_code', 'http://localhost:8083/portal-sso-callback,http://localhost:8080/login/oauth2/code/portal-app-oidc', 'http://localhost:8000/logged-out,http://localhost:8080/logged-out', 'openid,profile,email', '{"requireProofKey":false,"requireAuthorizationConsent":false}', '{"accessTokenFormat":"reference","authorizationCodeTimeToLive":"PT5M","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false}');
INSERT INTO `oauth2_registered_client` VALUES ('4', 'web-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, 'Web 应用客户端', 'client_secret_basic,client_secret_post', 'authorization_code,refresh_token,password', 'http://localhost:8081/callback,http://127.0.0.1:8081/callback', 'http://localhost:8081/logout', 'openid,profile,email,read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"idTokenSignatureAlgorithm":"RS256"}');
INSERT INTO `oauth2_registered_client` VALUES ('5', 'device-app', '2026-08-11 20:00:08', NULL, NULL, '设备码客户端', 'none', 'refresh_token,urn:ietf:params:oauth:grant-type:device_code', NULL, NULL, 'openid,profile,email,read', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT1H","reuseRefreshTokens":false}');
INSERT INTO `oauth2_registered_client` VALUES ('6', 'mobile-app', '2026-08-11 20:00:08', NULL, NULL, '移动应用客户端(PKCE)', 'none', 'authorization_code,refresh_token', 'com.example.mobileapp://oauth2/redirect,http://localhost:8083/callback', 'http://localhost:8083/logout', 'openid,profile,email,read,write', '{"requireProofKey":true,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT2H","reuseRefreshTokens":false,"idTokenSignatureAlgorithm":"RS256"}');
INSERT INTO `oauth2_registered_client` VALUES ('7', 'service-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '服务间调用客户端', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
INSERT INTO `oauth2_registered_client` VALUES ('8', 'admin-m2m', '2026-08-16 00:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理 M2M 服务凭证 (认证中心以机器身份执行管理写)', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');

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
  `user_label` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'client' COMMENT '业务标签 (仅展示/审计, 不参与准入判定): admin=管理端, client=客户端, wechat=微信端',
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
INSERT INTO `sys_user` VALUES (1, 'u_1a2b3c4d5e6f708090a0b0c0d0e0f001', 'admin', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '管理员', 'admin@example.com', NULL, NULL, 'admin', 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');
INSERT INTO `sys_user` VALUES (2, 'u_1a2b3c4d5e6f708090a0b0c0d0e0f002', 'user', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '普通用户', 'user@example.com', NULL, NULL, 'client', 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');

-- ----------------------------
-- Table structure for iam_tenant (租户目录, 权威在此)
-- ----------------------------
DROP TABLE IF EXISTS `iam_tenant_user`;
DROP TABLE IF EXISTS `iam_tenant`;
CREATE TABLE `iam_tenant`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '租户ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码',
  `tenant_name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户名称',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=禁用',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `tenant_code`(`tenant_code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '租户目录表 (身份层权威)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for iam_tenant_user (租户成员关系, 一人可属多租户, 下放引用用编码)
-- ----------------------------
CREATE TABLE `iam_tenant_user`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '关联ID',
  `tenant_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '租户编码 (关联 iam_tenant.tenant_code)',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '业务用户编码 (关联 sys_user.user_code)',
  `tenant_username` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '租户内账号 (可空, 默认同全局用户名)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '该租户内状态: 1=正常, 0=停用',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_tenant_user`(`tenant_code`, `user_code`) USING BTREE,
  INDEX `idx_user_code`(`user_code`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '租户-用户关系表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_tenant / iam_tenant_user
-- ----------------------------
INSERT INTO `iam_tenant` (id, tenant_code, tenant_name, status) VALUES (1, 'T001', '演示企业', 1);
INSERT INTO `iam_tenant_user` (tenant_code, user_code, tenant_username, status) VALUES
('T001', 'u_1a2b3c4d5e6f708090a0b0c0d0e0f001', 'admin', 1),
('T001', 'u_1a2b3c4d5e6f708090a0b0c0d0e0f002', 'user', 1);

-- ----------------------------
-- Table structure for iam_client_policy (客户端登录边界策略, 隔离管理端/门户端交叉登录)
-- ----------------------------
DROP TABLE IF EXISTS `iam_client_policy`;
CREATE TABLE `iam_client_policy`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.client_id)',
  `allowed_roles` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '允许登录该客户端的角色编码列表 (逗号分隔, 如 ADMIN; 空或*表示不限制)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '是否启用: 1=启用, 0=停用(默认放行)',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_client_id`(`client_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '客户端登录边界策略表 (管理端/门户端同库用户的交叉登录隔离)' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of iam_client_policy (admin-app 仅允许 ADMIN; portal-app 仅允许 USER)
-- ----------------------------
INSERT INTO `iam_client_policy` (id, client_id, allowed_roles, status, remark) VALUES
(1, 'admin-app', 'ADMIN', 1, '管理后台: 仅允许 ADMIN 角色登录'),
(2, 'portal-app', 'USER', 1, '门户前端: 仅允许 USER 角色登录');

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

SET FOREIGN_KEY_CHECKS = 1;