-- ============================================================
-- V6.2 数据库拆分 - 资源中心业务库 (业务 RBAC, 无影子用户表)
-- 数据库: iam_authorization
-- 归属: iam-resource-service
-- 表清单: sys_role / sys_permission / sys_role_permission / sys_user_role  (共 4 表)
-- 说明: 用户身份权威在认证中心 iam_identity.sys_user; 资源中心以业务用户编码
--       user_code (token sub) 直接关联 sys_user_role → sys_role, 不再维护影子用户表。
-- 基线: oauth2_server 单体库 (RBAC 部分结构保持一致)
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

SET FOREIGN_KEY_CHECKS = 1;