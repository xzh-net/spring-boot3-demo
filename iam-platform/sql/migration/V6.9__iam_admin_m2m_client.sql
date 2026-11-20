-- ============================================================
-- V6.9 迁移 - 认证中心新增 admin-m2m 客户端 (管理 M2M 服务凭证)
-- 【已废弃 · 勿重跑】A-P1-1 (2026-11-20): M2M / client_credentials 方案已整体废弃
--   (概要设计决策#1 单体无服务间调用; 静态服务凭证不可轮换/不可审计)。
--   令牌端点已摘除 client_credentials 转换器与提供者, 管理页选项与创建接口均已拒绝该 grant。
--   本文件仅作历史记录保留; 重跑会插入一个【换不到令牌的死客户端】。
--   将来若恢复 M2M: 须先过文档决策关 + 按 m2m.* scope 重建治理 (见 权限与安全设计.md)。
-- 归属: iam 库 / iam-authorization-server (合并后单服务)
-- 备注: 以 iam.sql (base) 为唯一来源; 本脚本供存量库手动执行。
-- ============================================================

USE iam;

INSERT IGNORE INTO `oauth2_registered_client` VALUES ('8', 'admin-m2m', '2026-08-16 00:00:00', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', NULL, '管理 M2M 服务凭证 (认证中心以机器身份执行管理写)', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read,write', '{"requireProofKey":false,"requireAuthorizationConsent":true}', '{"accessTokenFormat":"REFERENCE","accessTokenTimeToLive":"PT30M","reuseRefreshTokens":false}');
