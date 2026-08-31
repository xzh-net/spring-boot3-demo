-- V6.11 迁移 - 角色名称/备注细化 (iam_authorization.sys_role)
--
--   角色代码 (ADMIN/USER) 为逻辑主键 (内省/准入/授权主体判定均按 code), name/remark 仅作展示。
--   端名与 sys_user.user_label (admin=管理端, client=客户端) 中的「管理端」对齐, 用户端语义同「客户端」:
--     ADMIN → 名称「管理端」, 备注「拥有管理后端服务访问权限」
--     USER  → 名称「用户端」, 备注「拥有前端服务访问权限」

-- 1. ADMIN 角色 (幂等: 仅当仍是旧文案时更新; 用户已手动改名则不动)
UPDATE `sys_role`
SET `name` = '管理端', `remark` = '拥有管理后端服务访问权限'
WHERE `code` = 'ADMIN' AND (`name` = '管理员' OR `name` = '管理端');

-- 2. USER 角色
UPDATE `sys_role`
SET `name` = '用户端', `remark` = '拥有前端服务访问权限'
WHERE `code` = 'USER' AND (`name` = '普通用户' OR `name` = '客户端' OR `name` = '用户端');