/*
 Navicat Premium Data Transfer

 Source Server         : 192.168.31.161-8
 Source Server Type    : MySQL
 Source Server Version : 80410
 Source Host           : 192.168.31.161:3306
 Source Schema         : oauth2_server

 Target Server Type    : MySQL
 Target Server Version : 80410
 File Encoding         : 65001

 Date: 13/08/2026 10:08:31
*/

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
INSERT INTO `oauth2_registered_client` VALUES ('1', 'portal-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '门户应用 (SSO)', 'client_secret_basic', 'refresh_token,authorization_code', 'http://localhost:8083/portal-sso-callback,http://localhost:8081/portal-sso-callback,http://localhost:8080/login/oauth2/code/portal-app-oidc', 'http://localhost:8000/logged-out,http://localhost:8080/logged-out', 'openid,profile,email', '{\"requireProofKey\":false,\"requireAuthorizationConsent\":false}', '{\"accessTokenFormat\":\"reference\",\"authorizationCodeTimeToLive\":\"PT5M\",\"accessTokenTimeToLive\":\"PT2H\",\"reuseRefreshTokens\":false}');
INSERT INTO `oauth2_registered_client` VALUES ('2', 'web-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, 'Web 应用客户端', 'client_secret_basic,client_secret_post', 'authorization_code,refresh_token,password', 'http://localhost:8081/callback,http://127.0.0.1:8081/callback', 'http://localhost:8081/logout', 'openid,profile,email,read,write', '{\"requireProofKey\":false,\"requireAuthorizationConsent\":true}', '{\"accessTokenFormat\":\"REFERENCE\",\"accessTokenTimeToLive\":\"PT2H\",\"reuseRefreshTokens\":false,\"idTokenSignatureAlgorithm\":\"RS256\"}');
INSERT INTO `oauth2_registered_client` VALUES ('3', 'device-app', '2026-08-11 20:00:08', NULL, NULL, '设备码客户端', 'none', 'refresh_token,urn:ietf:params:oauth:grant-type:device_code', NULL, NULL, 'openid,profile,email,read', '{\"requireProofKey\":false,\"requireAuthorizationConsent\":true}', '{\"accessTokenFormat\":\"REFERENCE\",\"accessTokenTimeToLive\":\"PT1H\",\"reuseRefreshTokens\":false}');
INSERT INTO `oauth2_registered_client` VALUES ('4', 'mobile-app', '2026-08-11 20:00:08', NULL, NULL, '移动应用客户端(PKCE)', 'none', 'authorization_code,refresh_token', 'com.example.mobileapp://oauth2/redirect,http://localhost:8083/callback', 'http://localhost:8083/logout', 'openid,profile,email,read,write', '{\"requireProofKey\":true,\"requireAuthorizationConsent\":true}', '{\"accessTokenFormat\":\"REFERENCE\",\"accessTokenTimeToLive\":\"PT2H\",\"reuseRefreshTokens\":false,\"idTokenSignatureAlgorithm\":\"RS256\"}');
INSERT INTO `oauth2_registered_client` VALUES ('5', 'service-app', '2026-08-11 20:00:08', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '服务间调用客户端', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{\"requireProofKey\":false,\"requireAuthorizationConsent\":true}', '{\"accessTokenFormat\":\"REFERENCE\",\"accessTokenTimeToLive\":\"PT30M\",\"reuseRefreshTokens\":false}');
INSERT INTO `oauth2_registered_client` VALUES ('6', 'resource-server', '2026-08-13 09:56:12', '$2a$10$AJZZh81d5bT62axwVBkB9uGWYcavRwqLN7eW4X15DUYc2vqz1mQla', NULL, '资源服务器', 'client_secret_basic', 'client_credentials', '', '', 'read,write', '{\"requireProofKey\":false,\"requireAuthorizationConsent\":false}', '{\"accessTokenFormat\":\"reference\",\"authorizationCodeTimeToLive\":\"PT5M\",\"accessTokenTimeToLive\":\"PT30M\",\"reuseRefreshTokens\":false}');

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
-- Table structure for sys_user
-- ----------------------------
DROP TABLE IF EXISTS `sys_user`;
CREATE TABLE `sys_user`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `username` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '登录用户名',
  `password` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'BCrypt 加密后的密码',
  `nickname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '用户昵称',
  `email` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '电子邮箱',
  `phone` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '手机号码',
  `avatar` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '头像 URL',
  `role` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'ROLE_USER' COMMENT '角色: ROLE_ADMIN / ROLE_USER',
  `enabled` tinyint(1) NOT NULL DEFAULT 1 COMMENT '是否启用 (1=启用, 0=禁用)',
  `account_non_expired` tinyint(1) NOT NULL DEFAULT 1 COMMENT '账号是否未过期 (1=未过期, 0=已过期)',
  `account_non_locked` tinyint(1) NOT NULL DEFAULT 1 COMMENT '账号是否未锁定 (1=未锁定, 0=已锁定)',
  `credentials_non_expired` tinyint(1) NOT NULL DEFAULT 1 COMMENT '凭证是否未过期 (1=未过期, 0=已过期)',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `username`(`username`) USING BTREE,
  INDEX `idx_username`(`username`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 4 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '系统用户表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user
-- ----------------------------
INSERT INTO `sys_user` VALUES (1, 'admin', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '管理员', 'admin@example.com', NULL, NULL, 'ROLE_ADMIN', 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');
INSERT INTO `sys_user` VALUES (2, 'user', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '普通用户', 'user@example.com', NULL, NULL, 'ROLE_USER', 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08');

-- ----------------------------
-- Table structure for sys_user_role
-- ----------------------------
DROP TABLE IF EXISTS `sys_user_role`;
CREATE TABLE `sys_user_role`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '关联ID',
  `user_id` bigint(0) NOT NULL COMMENT '用户ID (关联 sys_user.id)',
  `role_id` bigint(0) NOT NULL COMMENT '角色ID (关联 sys_role.id)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_user_role`(`user_id`, `role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 3 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '用户-角色关联表' ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sys_user_role
-- ----------------------------
INSERT INTO `sys_user_role` VALUES (1, 1, 1);
INSERT INTO `sys_user_role` VALUES (2, 2, 2);

SET FOREIGN_KEY_CHECKS = 1;
