-- V6.4 迁移 - 主体编码化 (ROLE=sys_role.code, ORG=iam_org.org_code)
-- 背景: 「离开认证库用编码」原则, 业务表不存认证中心内部自增主键 id:
--   iam_app_authorization 的 ROLE 主体由 sys_role.id 统一为 sys_role.code,
--   ORG 主体由 iam_org.id 统一为 iam_org.org_code (与 USER=user_code 编码寻址一致)。
-- 本脚本为存量库升级的唯一执行途径 (由 DBA/升级账号手动执行)。
-- 注: 原 V6.4 含 tenant_id → tenant_code 编码化三段, 随租户功能整体移除, 已删除。
-- 新库 (iam.sql) 直接为主体编码结构, 无需执行。

USE iam;

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

-- 校验: iam_app_authorization.subject_id 均为主编码 (非数字)
