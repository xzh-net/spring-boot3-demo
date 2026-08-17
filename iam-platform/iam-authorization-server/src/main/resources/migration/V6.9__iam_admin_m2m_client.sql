-- ============================================================
-- V6.9 迁移 - 认证中心新增 admin-m2m 客户端 (管理 M2M 服务凭证)
-- 说明: 认证中心删除用户等管理操作时, 以该客户端 client_credentials 换取服务令牌
--       调用资源中心管理端能力 (/api/admin/**), 资源中心按 client_id 白名单
--       内省注入 ADMIN_SERVICE_TOKEN (管理服务凭证)。
-- 归属: iam_identity 库 / iam-authorization-server
-- 备注: 运行时由 DataInitializer.ensureAdminM2mClient() 兜底创建 (幂等);
--       本脚本供存量库手动执行 / 审计参考。
-- ============================================================

USE iam_identity;

INSERT IGNORE INTO `oauth2_registered_client` VALUES ('8', 'admin-m2m', '2026-08-16 00:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理 M2M 服务凭证 (认证中心以机器身份执行管理写)', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
