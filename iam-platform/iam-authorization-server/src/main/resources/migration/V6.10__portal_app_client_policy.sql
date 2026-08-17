-- ============================================================
-- V6.10 迁移 - 门户前端 portal-app 登录边界策略 (仅允许 USER 用户端角色)
-- 归属: iam_identity 库 / iam-authorization-server
-- 背景: 管理端与门户端用户统一于 iam_identity.sys_user 管理, 为隔离交叉登录,
--       门户经 portal-app 客户端授权码登录, 与 admin-app→ADMIN 对称,
--       该客户端仅允许用户端 (USER) 角色登录, admin 等其他角色不可进入门户。
-- 备注: 幂等, 按 client_id 主键; 若管理端已手动配置则不覆盖。
-- ============================================================

USE iam_identity;

INSERT INTO `iam_client_policy` (client_id, allowed_roles, status, remark)
VALUES ('portal-app', 'USER', 1, '门户前端: 管理端与门户端用户同库管理, 此客户端仅允许 USER 角色登录, 隔离管理端用户交叉登录')
ON DUPLICATE KEY UPDATE client_id = client_id;