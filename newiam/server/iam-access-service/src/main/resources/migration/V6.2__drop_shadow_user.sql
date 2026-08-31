-- ============================================================
-- V6.2 迁移 - 资源中心删除影子用户表 sys_user, 角色关联改按 user_code
-- 改造: 缺陷2 (改 sub / 删影子用户表 / 角色按 user_code 解析)
-- 归属: iam_authorization 库 / iam-resource-service
-- 说明: 用户身份权威在认证中心 iam_identity.sys_user;
--       资源中心仅保留 RBAC 4 表 (sys_role / sys_permission / sys_role_permission / sys_user_role)
-- ============================================================

USE iam_authorization;

-- 1) 若 sys_user_role 仍为 user_id 结构: 增加 user_code 列并跨库回填 (认证中心同实例 iam_identity 库)
ALTER TABLE `sys_user_role` ADD COLUMN `user_code` varchar(64) NULL AFTER `role_id`;
UPDATE `sys_user_role` ur
    JOIN iam_identity.`sys_user` u ON u.id = ur.user_id
    SET ur.user_code = u.user_code;

-- 2) 清理无法回填的孤儿关联
DELETE FROM `sys_user_role` WHERE `user_code` IS NULL OR `user_code` = '';

-- 3) 升级列 + 唯一索引 (DROP user_id 会连带删除旧 (user_id, role_id) 唯一索引)
ALTER TABLE `sys_user_role`
    DROP COLUMN `user_id`,
    MODIFY `user_code` varchar(64) NOT NULL,
    ADD UNIQUE INDEX `uk_user_code_role`(`user_code`, `role_id`);

-- 4) 删除影子用户表
DROP TABLE IF EXISTS `sys_user`;