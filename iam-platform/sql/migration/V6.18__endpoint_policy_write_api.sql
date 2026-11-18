-- V6.18 迁移 - 资源准入页开放维护写入口: 补三条写端点准入行 (policy:write)
--
-- 背景: 方案调整 (2026-11-18) —— iam_endpoint_policy 由"只读 + 迁移唯一写入方"改为
--       "种子初始化 + 管理页面维护 (读写 API), 上线后以库数据为准"; 运行期规则每请求直查 DB,
--       写入即刻生效。新增 POST/PUT/DELETE /admin/endpoint-policies 三个写端点,
--       按准入语义须显式声明 policy:write 权限档 (缺省表外=认证档, 不满足最小权限)。
--
-- 关键注记:
--   - 幂等可重复执行 (WHERE NOT EXISTS); 新库走基线 iam.sql 时由种子块同步补三行 (见基线);
--   - permission_id 按 policy:write 码反查 (不写死主键); policy_type=PERMISSION;
--   - service_key 与基线 / V6.17 默认值三处同步。

-- ============ 1. POST /admin/endpoint-policies (新增准入行) ============
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `permission_id`, `policy_type`, `service_key`, `status`)
SELECT 'POST', '/admin/endpoint-policies', 'policy:write', `p`.`id`, 'PERMISSION', 'iam-authorization-server', 1
FROM `sys_permission` `p`
WHERE `p`.`code` = 'policy:write'
  AND NOT EXISTS (
      SELECT 1 FROM `iam_endpoint_policy` `e`
      WHERE `e`.`service_key` = 'iam-authorization-server'
        AND `e`.`method` = 'POST' AND `e`.`path` = '/admin/endpoint-policies'
  );

-- ============ 2. PUT /admin/endpoint-policies/{id} (更新准入行) ============
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `permission_id`, `policy_type`, `service_key`, `status`)
SELECT 'PUT', '/admin/endpoint-policies/{id}', 'policy:write', `p`.`id`, 'PERMISSION', 'iam-authorization-server', 1
FROM `sys_permission` `p`
WHERE `p`.`code` = 'policy:write'
  AND NOT EXISTS (
      SELECT 1 FROM `iam_endpoint_policy` `e`
      WHERE `e`.`service_key` = 'iam-authorization-server'
        AND `e`.`method` = 'PUT' AND `e`.`path` = '/admin/endpoint-policies/{id}'
  );

-- ============ 3. DELETE /admin/endpoint-policies/{id} (删除准入行) ============
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `permission_id`, `policy_type`, `service_key`, `status`)
SELECT 'DELETE', '/admin/endpoint-policies/{id}', 'policy:write', `p`.`id`, 'PERMISSION', 'iam-authorization-server', 1
FROM `sys_permission` `p`
WHERE `p`.`code` = 'policy:write'
  AND NOT EXISTS (
      SELECT 1 FROM `iam_endpoint_policy` `e`
      WHERE `e`.`service_key` = 'iam-authorization-server'
        AND `e`.`method` = 'DELETE' AND `e`.`path` = '/admin/endpoint-policies/{id}'
  );
