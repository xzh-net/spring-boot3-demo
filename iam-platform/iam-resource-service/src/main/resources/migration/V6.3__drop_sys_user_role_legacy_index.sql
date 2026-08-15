-- ============================================================
-- V6.3 迁移 - 资源中心清理 sys_user_role 历史遗留单列唯一索引
-- 背景: 旧版启动库曾在 sys_user_role 上建单列唯一索引 uk_user_role(role_id),
--       该索引会阻止多用户绑定同一角色 (Duplicate entry 'x' for key
--       'sys_user_role.uk_user_role')。V6.2 的 DROP COLUMN user_id 不会删除它
--       (它建在 role_id 上), 故需手动清理, 以 uk_user_code_role(user_code, role_id)
--       复合唯一索引为准。
-- 归属: iam_authorization 库 / iam-resource-service
-- 执行: 手动执行 (应用启动时 ShadowUserMigrationInitializer 也会幂等自愈)
-- ============================================================

USE iam_authorization;

-- 仅当存在"单列 role_id"的 uk_user_role 索引时才删除
SET @idx_cols = (
    SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index)
    FROM information_schema.statistics
    WHERE table_schema = 'iam_authorization'
      AND table_name = 'sys_user_role'
      AND index_name = 'uk_user_role'
);

SET @sql = IF(
    @idx_cols = 'role_id',
    'ALTER TABLE sys_user_role DROP INDEX uk_user_role',
    'SELECT ''uk_user_role 无需清理 (列: '' + COALESCE(@idx_cols, ''不存在'') + '')'''
);

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 校验结果: 应仅剩 PRIMARY(id) 与 uk_user_code_role(user_code, role_id)
SELECT index_name, GROUP_CONCAT(column_name ORDER BY seq_in_index) AS cols
FROM information_schema.statistics
WHERE table_schema = 'iam_authorization' AND table_name = 'sys_user_role'
GROUP BY index_name;
