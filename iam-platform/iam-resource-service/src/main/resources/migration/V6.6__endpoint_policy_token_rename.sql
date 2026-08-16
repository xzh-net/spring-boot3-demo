-- V6.6 迁移 - 准入要求取最新语义 + 令牌类别更名 (iam_endpoint_policy)
-- 背景:
--   1) 门户域 (portal) 不再「任意放行」: 由 PERMIT_ALL 收紧为 PORTAL_SERVICE_TOKEN (门户服务凭证);
--      portal 域还叠加 authserver.portal-client-ids 门户客户端白名单, 双闸门;
--      门户应用客户端 (portal-app) 签发的用户/服务令牌由内省器注入该凭证;
--   2) 令牌类别更名: MANAGEMENT_TOKEN (管理令牌) -> ADMIN_SERVICE_TOKEN (管理服务凭证),
--      SERVICE_TOKEN (服务令牌) -> PORTAL_SERVICE_TOKEN (门户服务凭证);
--   3) 新增放行域 permitall (controller/permitall, /api/permitall/time), 行由启动扫描播种, 不在此手填。
-- 说明: 本脚本仅处理存量行; 新库由 EndpointPolicyScanInitializer 扫描播种新语义,
--       且 coded 行会在启动时自动对齐代码默认并对齐清理失效端点 (override 行不受影响), 脚本重复执行幂等。
-- 适用库: iam_authorization

USE iam_authorization;

-- 1. portal 域默认收紧为门户服务凭证（coded/override 行统一升级, 符合最新语义）
UPDATE `iam_endpoint_policy` SET `required_authority` = 'PORTAL_SERVICE_TOKEN', `remark` = IFNULL(`remark`, '')
WHERE `domain` = 'portal' AND `required_authority` IN ('PERMIT_ALL', 'AUTHENTICATED', 'PORTAL_SERVICE_TOKEN');

-- 2. 令牌类别更名: 管理令牌 -> 管理服务凭证
UPDATE `iam_endpoint_policy` SET `required_authority` = 'ADMIN_SERVICE_TOKEN', `remark` = IFNULL(`remark`, '')
WHERE `required_authority` IN ('MANAGEMENT_TOKEN', 'ROLE_ADMIN');

-- 3. 令牌类别更名: 服务令牌 -> 门户服务凭证
UPDATE `iam_endpoint_policy` SET `required_authority` = 'PORTAL_SERVICE_TOKEN', `remark` = IFNULL(`remark`, '')
WHERE `required_authority` IN ('SERVICE_TOKEN', 'ROLE_SERVICE');