-- V6.8 迁移 - 收编放行域 permitall (iam_endpoint_policy)
-- 背景:
--   TimeController 作为「不需要权限的接口」示例, 不再单列放行域 permitall;
--   controller/permitall 包归 other (其他) 域, required_authority 仍为 PERMIT_ALL (放行)。
-- 说明: coded 行重启时由 EndpointPolicyScanInitializer 自动对齐域与准入 (override 不受影响),
--       本脚本仅处理存量域值, 重复执行幂等。
-- 适用库: iam_authorization

USE iam_authorization;

-- 1. 存量 permitall 域改归 other (不需要权限的接口示例)
UPDATE `iam_endpoint_policy` SET `domain` = 'other'
WHERE `domain` = 'permitall';