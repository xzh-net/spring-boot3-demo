-- V6.14 迁移 - 权限表重构: sys_permission 字典化 + admin 域准入行改绑权限码
--
-- 背景: 打通"角色-权限-端点"三段式授权。用户令牌经 RbacAuthoritiesOpaqueTokenIntrospector 注入权限码,
--       iam_endpoint_policy.required_authority 直接以权限码作为端点准入要求, 实现端点级细粒度控制。
--       原 type=app 的 5 条 app:* 码运行时零消费 (无 hasAuthority / canAccessApp 已删), 一并清除。
--
-- 变更内容:
--   1) sys_permission: 删 type 列, 增 domain(admin/portal/third) / status(1启用0停用) / update_time;
--      code 注释改为 API 权限码语义 (如 user:read)。一次性 DDL, 不可重复执行。
--   2) 删除 5 条 app:* 死码及其 sys_role_permission 绑定。
--   3) 新增 14 个管理端 API 权限码 (domain=admin, status=1), ADMIN(id=1) 绑定全部 14 码。
--   4) admin 域 49 行准入由粗档 ADMIN_SERVICE_TOKEN 改绑权限码。
--
-- 关键注记:
--   - source='override' 是必须的: EndpointPolicyService.rescan() 启动时会把 coded 行的 required_authority
--     重置回域默认 (admin→ADMIN_SERVICE_TOKEN), 只有 override 行播种/剪除/对齐全跳过, 改码不被重启冲掉。
--     新库走基线 iam.sql 时 admin 49 行同样以 override 预置, 两环境状态一致。
--   - defaultAuthorityOf 不改: 新端点仍按域播粗档, 需要细化时人工改码 (两档并存)。
--   - 无权限回归: 内省器对含 ADMIN 角色的用户令牌仍追加 ADMIN_SERVICE_TOKEN (与 client 无关);
--     service 令牌只注入域令牌无权限码, 改码后在 admin 端点仍被拒 (预期收紧)。

-- ============ 1. sys_permission 结构重构 ============
ALTER TABLE `sys_permission`
  DROP COLUMN `type`,
  ADD COLUMN `domain` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'admin' COMMENT '能力域: admin=管理端/portal=门户/third=三方' AFTER `name`,
  ADD COLUMN `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用' AFTER `domain`,
  ADD COLUMN `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间' AFTER `create_time`,
  MODIFY COLUMN `code` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '权限标识 (API 权限码, 如 user:read)',
  ADD INDEX `idx_domain`(`domain`) USING BTREE;

-- ============ 2. 清除 5 条 app:* 死码及角色绑定 ============
DELETE `rp` FROM `sys_role_permission` `rp`
  JOIN `sys_permission` `p` ON `p`.`id` = `rp`.`permission_id`
  WHERE `p`.`code` LIKE 'app:%';
DELETE FROM `sys_permission` WHERE `code` LIKE 'app:%';

-- ============ 3. 14 个管理端 API 权限码 (id 1-14, domain=admin, status=1) ============
INSERT INTO `sys_permission` (`id`, `code`, `name`, `domain`, `status`, `remark`) VALUES
(1,  'user:read',         '用户查看',   'admin', 1, '用户列表/详情/用户会话查询'),
(2,  'user:write',        '用户管理',   'admin', 1, '用户增删改/启停/重置密码/踢会话/数据清理'),
(3,  'role:read',         '角色查看',   'admin', 1, '角色列表/用户-角色查询'),
(4,  'role:write',        '角色管理',   'admin', 1, '角色增删改/用户-角色绑定'),
(5,  'session:read',      '会话查看',   'admin', 1, '在线会话/用户会话查询'),
(6,  'session:write',     '会话管理',   'admin', 1, '按会话/在线条目/用户强制下线'),
(7,  'application:read',  '应用查看',   'admin', 1, '应用列表/授权/渠道查询'),
(8,  'application:write', '应用管理',   'admin', 1, '应用增删改/授权配置/渠道增删改'),
(9,  'client:read',       '客户端查看', 'admin', 1, 'OAuth2 客户端列表/详情/准入策略查询'),
(10, 'client:write',      '客户端管理', 'admin', 1, 'OAuth2 客户端增删改/密钥重置/准入策略配置'),
(11, 'permission:read',   '权限查看',   'admin', 1, '权限码列表'),
(12, 'permission:write',  '权限管理',   'admin', 1, '权限码增删改 (准入引用中的码禁止删除)'),
(13, 'record:read',       '记录查看',   'admin', 1, '授权记录/consent 记录查询'),
(14, 'record:write',      '记录管理',   'admin', 1, '授权记录清空');

-- ============ 4. ADMIN(id=1) 绑定全部 14 码 ============
INSERT INTO `sys_role_permission` (`id`, `role_id`, `permission_id`) VALUES
(1, 1, 1),  (2, 1, 2),  (3, 1, 3),  (4, 1, 4),  (5, 1, 5),  (6, 1, 6),  (7, 1, 7),
(8, 1, 8),  (9, 1, 9),  (10, 1, 10), (11, 1, 11), (12, 1, 12), (13, 1, 13), (14, 1, 14);

-- ============ 5. admin 域 49 行改绑权限码 (source=override 防 rescan 回写) ============
UPDATE `iam_endpoint_policy` SET `required_authority` = 'user:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/users'),
    ('GET', '/api/admin/users/{id}'),
    ('GET', '/api/admin/users/{id}/sessions')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'user:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/users'),
    ('PUT', '/api/admin/users/{id}'),
    ('DELETE', '/api/admin/users/{id}'),
    ('PUT', '/api/admin/users/{id}/enable'),
    ('POST', '/api/admin/users/{id}/reset-password'),
    ('DELETE', '/api/admin/users/{id}/sessions'),
    ('DELETE', '/api/admin/users/{userCode}/data')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'role:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/roles'),
    ('GET', '/api/admin/user-roles/{userCode}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'role:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/roles'),
    ('PUT', '/api/admin/roles/{id}'),
    ('DELETE', '/api/admin/roles/{id}'),
    ('PUT', '/api/admin/user-roles/{userCode}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'session:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/sessions/online'),
    ('GET', '/api/admin/sessions/users/{id}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'session:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/sessions/{ssoSessionId}/logout'),
    ('DELETE', '/api/admin/sessions/online/{username}'),
    ('POST', '/api/admin/sessions/users/{id}/logout')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'application:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/applications'),
    ('GET', '/api/admin/applications/{appId}/authorizations'),
    ('GET', '/api/admin/applications/{appId}/channels')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'application:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/applications'),
    ('PUT', '/api/admin/applications/{id}'),
    ('DELETE', '/api/admin/applications/{id}'),
    ('POST', '/api/admin/applications/authorizations'),
    ('DELETE', '/api/admin/applications/authorizations/{id}'),
    ('POST', '/api/admin/applications/{appId}/channels'),
    ('PUT', '/api/admin/applications/{appId}/channels/{channelId}'),
    ('DELETE', '/api/admin/applications/{appId}/channels/{channelId}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'client:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/clients'),
    ('GET', '/api/admin/clients/{id}'),
    ('GET', '/api/admin/policies'),
    ('GET', '/api/admin/policies/{clientId}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'client:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/clients'),
    ('PUT', '/api/admin/clients/{id}'),
    ('DELETE', '/api/admin/clients/{id}'),
    ('POST', '/api/admin/clients/{id}/reset-secret'),
    ('POST', '/api/admin/policies'),
    ('DELETE', '/api/admin/policies/{clientId}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'permission:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/permissions')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'permission:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('POST', '/api/admin/permissions'),
    ('PUT', '/api/admin/permissions/{id}'),
    ('DELETE', '/api/admin/permissions/{id}')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'record:read', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('GET', '/api/admin/records'),
    ('GET', '/api/admin/records/consents')
  );

UPDATE `iam_endpoint_policy` SET `required_authority` = 'record:write', `source` = 'override'
  WHERE `domain` = 'admin' AND (`method`, `path`) IN (
    ('DELETE', '/api/admin/records')
  );
