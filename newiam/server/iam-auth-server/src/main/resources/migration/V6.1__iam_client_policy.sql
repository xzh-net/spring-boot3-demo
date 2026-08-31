-- ============================================================
-- V6.1 迁移 - 认证中心新增 iam_client_policy (客户端登录边界策略表)
-- 背景: 管理端用户与门户端用户统一在 iam_identity.sys_user 管理, 用该表限定各客户端
--       允许登录的角色集合, 隔离管理端/门户端用户交叉登录 (原 yaml client-identity-policy)
-- 归属: iam_identity 库 / iam-authorization-server
-- 备注: 用户业务 RBAC 角色权威在资源中心 iam_authorization (sys_user_role)
-- ============================================================

USE iam_identity;

CREATE TABLE IF NOT EXISTS `iam_client_policy`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '客户端ID (关联 oauth2_registered_client.client_id)',
  `allowed_roles` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '允许登录该客户端的角色编码列表 (逗号分隔, 如 ADMIN; 空或*表示不限制)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '是否启用: 1=启用, 0=停用(默认放行)',
  `remark` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uk_client_id`(`client_id`)
) ENGINE = InnoDB AUTO_INCREMENT = 2 DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '客户端登录边界策略表 (管理端/门户端同库用户的交叉登录隔离)';

-- 等价迁移原 yaml 配置: admin-app 仅允许 ADMIN 角色, 隔离门户端用户交叉登录
INSERT IGNORE INTO `iam_client_policy` (id, client_id, allowed_roles, status, remark) VALUES
(1, 'admin-app', 'ADMIN', 1, '管理后台: 管理端与门户端用户同库管理, 此客户端仅允许 ADMIN 角色登录, 隔离门户端用户交叉登录');