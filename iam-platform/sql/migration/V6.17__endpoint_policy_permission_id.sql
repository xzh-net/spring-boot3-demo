-- V6.17 迁移 - iam_endpoint_policy 引用重构: required_authority 字符串 → permission_id + policy_type + service_key
--
-- 背景: P0-2 终稿 (落表路线)。required_authority 以字符串引用 sys_permission.code, 无完整性保护:
--       改名 → 引用行静默失联 (端点对所有令牌永久 403); 删除 → 无约束悬空。改用 permission_id
--       稳定身份 + FK RESTRICT 数据库强制; policy_type 显式声明策略档 (不以 permission_id IS NULL
--       推断, 预留 PUBLIC 等扩展); service_key 预留服务命名空间 (多服务共表防路径冲突, 单体阶段固定值)。
--
-- 变更内容 (七步; 旧字符串列 required_authority 本轮保留, 由后续 V6.18 删除):
--   1) 加列 permission_id / policy_type / service_key
--   2) 回填 permission_id + policy_type (按码关联, 一句双 SET)
--   3) 档位行修正 (PERMIT_ALL; AUTHENTICATED 靠列默认值)
--   4) 孤儿检查 (人工核对: 必须 0 行, 否则中止排查)
--   5) CHECK 约束 (机器强制: PERMISSION ⟺ id 非空; 非档位码行未回填也拦 → 存量孤儿 DDL 报错即停)
--   6) FK ×2: iam_endpoint_policy + sys_scope_permission → sys_permission (ON DELETE RESTRICT)
--   7) 唯一键 uk_endpoint(method,path) → (service_key,method,path)
--
-- 关键注记:
--   - 部署顺序: **先执行本迁移, 再部署新代码** (实体含新字段, 表缺列则启动查询直接报错);
--   - service_key 固定 'iam-authorization-server' (本服务 artifactId), 与基线 iam.sql 同值, 变更须两处同步;
--   - policy_type 取值与执法器三档一一对应: PERMISSION (权限码) / AUTHENTICATED / PERMIT_ALL;
--   - 回填正确性: 码行全部匹配成功 (孤儿=0), 档位行保持档位, 匹配失败不允许静默变 NULL;
--   - 一次性 DDL 不可重复执行 (加列/加约束重复执行会报错);
--   - 应用层守卫同批切源 (RbacService: 删除守卫按 permission_id 计数 + sys_scope_permission 双守卫)。

-- ============ 1. 加列 ============
ALTER TABLE `iam_endpoint_policy`
  ADD COLUMN `permission_id` bigint NULL COMMENT '所需权限 ID → sys_permission.id (档位行恒 NULL)' AFTER `required_authority`,
  ADD COLUMN `policy_type` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'AUTHENTICATED' COMMENT '策略类型: PERMISSION=权限码 / AUTHENTICATED=认证档 / PERMIT_ALL=全放行' AFTER `permission_id`,
  ADD COLUMN `service_key` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'iam-authorization-server' COMMENT '服务命名空间 (多服务共表预留, 单体阶段固定值)' AFTER `policy_type`;

-- ============ 2. 回填 permission_id + policy_type (码行; 档位行不匹配 JOIN, 保持默认) ============
UPDATE `iam_endpoint_policy` `ep`
  JOIN `sys_permission` `p` ON `p`.`code` = `ep`.`required_authority`
  SET `ep`.`permission_id` = `p`.`id`,
      `ep`.`policy_type` = 'PERMISSION'
 WHERE `ep`.`required_authority` NOT IN ('AUTHENTICATED', 'PERMIT_ALL');

-- ============ 3. 档位行修正 (PERMIT_ALL; AUTHENTICATED 已靠列默认值) ============
UPDATE `iam_endpoint_policy`
   SET `policy_type` = 'PERMIT_ALL'
 WHERE `required_authority` = 'PERMIT_ALL';

-- ============ 4. 孤儿检查 (人工核对: 必须返回 0 行; 有结果 = 码行回填失败, 禁止继续) ============
SELECT `id`, `method`, `path`, `required_authority`
  FROM `iam_endpoint_policy`
 WHERE `required_authority` NOT IN ('AUTHENTICATED', 'PERMIT_ALL')
   AND `permission_id` IS NULL;

-- ============ 5. CHECK 约束 (机器强制; 第 4 步若有孤儿, 本句 DDL 直接报错即停) ============
ALTER TABLE `iam_endpoint_policy`
  ADD CONSTRAINT `chk_endpoint_policy_type` CHECK (
    (`policy_type` = 'PERMISSION' AND `permission_id` IS NOT NULL) OR
    (`policy_type` <> 'PERMISSION' AND `permission_id` IS NULL
      AND `required_authority` IN ('AUTHENTICATED', 'PERMIT_ALL'))
  );

-- ============ 6. 外键 (ON DELETE RESTRICT: 被端点/范围引用的权限禁止删除) ============
ALTER TABLE `iam_endpoint_policy`
  ADD CONSTRAINT `fk_endpoint_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT;

ALTER TABLE `sys_scope_permission`
  ADD CONSTRAINT `fk_scope_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT;

-- ============ 7. 唯一键加服务位 (service_key 预留多服务命名空间) ============
ALTER TABLE `iam_endpoint_policy`
  DROP INDEX `uk_endpoint`,
  ADD UNIQUE INDEX `uk_endpoint`(`service_key`, `method`, `path`) USING BTREE;
