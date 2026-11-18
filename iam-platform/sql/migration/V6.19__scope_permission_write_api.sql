-- V6.19 迁移 - 权限管理页开放「所属授权范围」维护: 补两条映射写端点准入行 (permission:write)
--
-- 背景: Q1A/Q2A/Q3A 裁定 (2026-11-18) —— sys_scope_permission 映射行由「仅 SQL 种子」放开为
--       页面维护 (权限管理页「所属授权范围」列, 弹窗勾选组), 组定义 sys_scope 仍走种子;
--       写接口挂 permission:write 域, 内省层实时展开、保存即时生效。
--       新增 POST/DELETE /admin/permissions/{id}/scopes/{scopeId} 两个端点, 按准入语义补显式准入行。
--
-- 关键注记:
--   - 幂等可重复执行 (WHERE NOT EXISTS); 新库走基线 iam.sql 种子块同步 (见基线);
--   - permission_id 按 permission:write 码反查 (不写死主键); policy_type=PERMISSION;
--   - service_key 与基线 / V6.17 / V6.18 默认值同步。

-- ============ 1. POST /admin/permissions/{id}/scopes/{scopeId} (加入组) ============
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `permission_id`, `policy_type`, `service_key`, `status`)
SELECT 'POST', '/admin/permissions/{id}/scopes/{scopeId}', 'permission:write', `p`.`id`, 'PERMISSION', 'iam-authorization-server', 1
FROM `sys_permission` `p`
WHERE `p`.`code` = 'permission:write'
  AND NOT EXISTS (
      SELECT 1 FROM `iam_endpoint_policy` `e`
      WHERE `e`.`service_key` = 'iam-authorization-server'
        AND `e`.`method` = 'POST' AND `e`.`path` = '/admin/permissions/{id}/scopes/{scopeId}'
  );

-- ============ 2. DELETE /admin/permissions/{id}/scopes/{scopeId} (移出组) ============
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `permission_id`, `policy_type`, `service_key`, `status`)
SELECT 'DELETE', '/admin/permissions/{id}/scopes/{scopeId}', 'permission:write', `p`.`id`, 'PERMISSION', 'iam-authorization-server', 1
FROM `sys_permission` `p`
WHERE `p`.`code` = 'permission:write'
  AND NOT EXISTS (
      SELECT 1 FROM `iam_endpoint_policy` `e`
      WHERE `e`.`service_key` = 'iam-authorization-server'
        AND `e`.`method` = 'DELETE' AND `e`.`path` = '/admin/permissions/{id}/scopes/{scopeId}'
  );
