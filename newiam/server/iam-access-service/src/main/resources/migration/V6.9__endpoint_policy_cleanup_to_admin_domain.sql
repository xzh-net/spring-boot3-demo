-- V6.9 迁移 - 用户关联数据清理接口归管理端能力 (iam_endpoint_policy)
-- 背景:
--   按开发规范 (设计说明书 §23.4) 管理写操作不应混入 controller/internal (对标认证中心只读内省),
--   删除用户联动清理从 /api/internal/user/{userCode}/data (internal 域, PORTAL_SERVICE_TOKEN)
--   迁至 /api/admin/users/{userCode}/data (admin 域, ADMIN_SERVICE_TOKEN, 管理 M2M 凭证把关)。
-- 说明: coded 行重启时由 EndpointPolicyScanInitializer 自动对齐 (旧路径清理 + 新路径补种,
--       override 不受影响), 本脚本仅显式移除旧路径存量行, 重复执行幂等。
-- 适用库: iam_authorization

USE iam_authorization;

-- 1. 移除已废弃的 internal 用户数据清理准入行 (路径已迁至 /api/admin**, 新行由扫描播种)
DELETE FROM `iam_endpoint_policy`
WHERE `method` = 'DELETE' AND `path` = '/api/internal/user/{userCode}/data';