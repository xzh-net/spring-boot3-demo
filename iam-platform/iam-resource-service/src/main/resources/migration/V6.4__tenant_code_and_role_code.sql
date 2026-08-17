-- V6.4 迁移 - 资源中心编码化引用 (tenant_id → tenant_code; ROLE/ORG 主体编码化)
-- 背景: 「离开认证库用编码」原则, 资源中心业务库不存认证中心内部自增主键 id:
--   * iam_application / iam_org / iam_app_authorization 的 tenant_id 改为 tenant_code;
--   * iam_app_authorization 的 ROLE 主体由 sys_role.id 统一为 sys_role.code,
--     ORG 主体由 iam_org.id 统一为 iam_org.org_code (与 USER=user_code 编码寻址一致)。
-- 本脚本为存量库升级的唯一执行途径 (由 DBA/升级账号手动执行, 可跨库 JOIN iam_identity 回填);
-- 新库 (iam_authorization.sql V6.4) 直接为编码结构, 无需执行。

USE iam_authorization;

-- ============ iam_application: tenant_id → tenant_code ============
ALTER TABLE iam_application ADD COLUMN tenant_code varchar(64) NULL;
UPDATE iam_application a LEFT JOIN iam_identity.iam_tenant t ON t.id = a.tenant_id SET a.tenant_code = t.tenant_code;
UPDATE iam_application SET tenant_code = 'T001' WHERE tenant_code IS NULL OR tenant_code = '';
ALTER TABLE iam_application DROP COLUMN tenant_id, MODIFY tenant_code varchar(64) NOT NULL;

-- ============ iam_org: tenant_id → tenant_code ============
ALTER TABLE iam_org ADD COLUMN tenant_code varchar(64) NULL;
UPDATE iam_org o LEFT JOIN iam_identity.iam_tenant t ON t.id = o.tenant_id SET o.tenant_code = t.tenant_code;
UPDATE iam_org SET tenant_code = 'T001' WHERE tenant_code IS NULL OR tenant_code = '';
ALTER TABLE iam_org DROP COLUMN tenant_id, MODIFY tenant_code varchar(64) NOT NULL;

-- ============ iam_app_authorization: 主体编码化 + tenant 编码化 ============
-- 1) ROLE 主体 sys_role.id → sys_role.code
UPDATE iam_app_authorization a JOIN sys_role r ON a.subject_id = CAST(r.id AS CHAR)
    SET a.subject_id = r.code WHERE a.subject_type = 'ROLE';
-- 2) ORG 主体 iam_org.id → iam_org.org_code
UPDATE iam_app_authorization a JOIN iam_org o ON a.subject_id = CAST(o.id AS CHAR)
    SET a.subject_id = o.org_code WHERE a.subject_type = 'ORG';
-- 3) 清理未解析的孤儿主体
DELETE FROM iam_app_authorization
WHERE (subject_type = 'ROLE' AND NOT EXISTS (SELECT 1 FROM sys_role r WHERE r.code = subject_id))
   OR (subject_type = 'ORG'  AND NOT EXISTS (SELECT 1 FROM iam_org o WHERE o.org_code = subject_id));
-- 4) tenant_id → tenant_code (先移除唯一索引避免 DROP 列连带删除)
ALTER TABLE iam_app_authorization DROP INDEX uk_authz, ADD COLUMN tenant_code varchar(64) NULL;
UPDATE iam_app_authorization a LEFT JOIN iam_identity.iam_tenant t ON t.id = a.tenant_id SET a.tenant_code = t.tenant_code;
UPDATE iam_app_authorization SET tenant_code = 'T001' WHERE tenant_code IS NULL OR tenant_code = '';
ALTER TABLE iam_app_authorization DROP COLUMN tenant_id,
    MODIFY tenant_code varchar(64) NOT NULL,
    ADD UNIQUE INDEX uk_authz(tenant_code, app_id, channel_id, subject_type, subject_id);

-- 校验: 三表应均无 tenant_id 列; iam_app_authorization.subject_id 均为主编码 (非数字)