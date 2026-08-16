-- V6.4 迁移 - 认证中心 iam_tenant_user 下放引用编码化
-- 背景: 租户成员关系离开认证库引用时需用业务编码, 不再引用内部自增主键
--       (与 sys_user.user_code / iam_tenant.tenant_code 的编码化原则一致)。
-- 实际迁移由 TenantUserMigrationInitializer (ApplicationRunner) 幂等执行, 本脚本仅供参考/审计。
-- 新库 (iam_identity.sql V6.4) 直接为编码结构, 无需执行。

USE iam_identity;

-- 1) 新增编码列
ALTER TABLE iam_tenant_user
    ADD COLUMN tenant_code varchar(64) NULL,
    ADD COLUMN user_code varchar(64) NULL;

-- 2) 跨表按 id 回填编码
UPDATE iam_tenant_user tu JOIN iam_tenant t ON t.id = tu.tenant_id SET tu.tenant_code = t.tenant_code;
UPDATE iam_tenant_user tu JOIN sys_user u ON u.id = tu.user_id SET tu.user_code = u.user_code;

-- 3) 清理无法回填的孤儿关联
DELETE FROM iam_tenant_user
WHERE tenant_code IS NULL OR tenant_code = '' OR user_code IS NULL OR user_code = '';

-- 4) 移除旧列 (连带删除其上的 uk_tenant_user / idx_user 索引), 重建编码索引
ALTER TABLE iam_tenant_user
    DROP COLUMN tenant_id,
    DROP COLUMN user_id,
    MODIFY tenant_code varchar(64) NOT NULL,
    MODIFY user_code varchar(64) NOT NULL,
    ADD UNIQUE INDEX uk_tenant_user(tenant_code, user_code),
    ADD INDEX idx_user_code(user_code);

-- 校验结果: iam_tenant_user 应仅剩 id / tenant_code / user_code / tenant_username / status / create_time / update_time