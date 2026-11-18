-- V6.20 迁移 - 端点准入拆表: iam_endpoint_policy → iam_endpoint (资源) + iam_endpoint_permission (绑定)
--
-- 背景: 业务要求「一个端点需要多个权限」(1:N) —— 原结构 permission_id 单列隐含 1:1, 无法表达
--       权限组合 (ALL=同时具备 / ANY=任一即可)。拆表后: 资源与绑定分离, 档位行 (AUTHENTICATED/
--       PERMIT_ALL) 无绑定留资源表, PERMISSION 行在绑定表 1..N。
--       同批: D1B 表改名 iam_endpoint / D2A endpoint_id ON DELETE CASCADE / D3A 顺路删过渡列
--       required_authority (V6.17 起使命完成) / D4A 运行时三查直查。
--
-- 关键注记:
--   - 一次性 DDL 不可重复执行; 与基线 iam.sql 同构 (新库直接建新结构);
--   - 数据搬迁基于旧列 permission_id (第 4 步执行时旧列仍在, 先搬后删);
--   - reset-init verify 断言 tables 17 → 18 (净增绑定表一张), 已同步修改;
--   - uk_endpoint(service_key,method,path) 与 service_key 不受影响。

-- ============ 1. 资源表改名 (索引/FK/CHECK 随表自动跟随) ============
RENAME TABLE `iam_endpoint_policy` TO `iam_endpoint`;

-- ============ 2. 删旧 CHECK (引用即将删除的 permission_id / required_authority 列) ============
ALTER TABLE `iam_endpoint` DROP CHECK `chk_endpoint_policy_type`;

-- ============ 3. 建绑定表 ============
CREATE TABLE `iam_endpoint_permission`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '绑定ID',
  `endpoint_id` bigint(0) NOT NULL COMMENT '→ iam_endpoint.id (资源行)',
  `permission_id` bigint(0) NOT NULL COMMENT '→ sys_permission.id (所需权限码)',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_endpoint_permission`(`endpoint_id`, `permission_id`) USING BTREE,
  CONSTRAINT `fk_ee_endpoint` FOREIGN KEY (`endpoint_id`) REFERENCES `iam_endpoint` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT `fk_ee_permission` FOREIGN KEY (`permission_id`) REFERENCES `sys_permission` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '端点↔权限绑定 (policy_type=PERMISSION 行使用, 一端点多权限 1:N)' ROW_FORMAT = Dynamic;

-- ============ 4. 数据搬迁 (旧列 permission_id → 绑定表; 先搬后删) ============
INSERT INTO `iam_endpoint_permission` (`endpoint_id`, `permission_id`)
SELECT `id`, `permission_id` FROM `iam_endpoint`
 WHERE `policy_type` = 'PERMISSION' AND `permission_id` IS NOT NULL;

-- ============ 5. 加组合语义列 ============
ALTER TABLE `iam_endpoint`
  ADD COLUMN `permission_logic` varchar(3) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT 'ALL' COMMENT '组合语义: ALL=全部满足 / ANY=任一满足 (仅 PERMISSION 行有意义)' AFTER `policy_type`,
  ADD CONSTRAINT `chk_permission_logic` CHECK (`permission_logic` IN ('ALL', 'ANY'));

-- ============ 6. 删旧列 (先删 FK 再删列; required_authority 过渡列一并删除) ============
ALTER TABLE `iam_endpoint` DROP FOREIGN KEY `fk_endpoint_permission`;
ALTER TABLE `iam_endpoint` DROP COLUMN `permission_id`;
ALTER TABLE `iam_endpoint` DROP COLUMN `required_authority`;

-- ============ 7. 核对 (期望: 资源 54 / 绑定 54) ============
SELECT (SELECT COUNT(*) FROM `iam_endpoint`) AS resources,
       (SELECT COUNT(*) FROM `iam_endpoint_permission`) AS links,
       (SELECT COUNT(*) FROM `iam_endpoint` WHERE `policy_type` = 'PERMISSION') AS perm_rows;
