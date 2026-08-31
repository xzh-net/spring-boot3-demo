-- V6.10 迁移 - internal 域收编为硬规则 (iam_endpoint_policy)
--
--   按确认方案: /api/internal/** 仅供认证中心 M2M (resource-server) 调用, 属**硬规则**,
--   不进入 iam_endpoint_policy 规则表, 不支持管理端 override (EndpointAdmissionManager 前置裁决)。
--   扫描初始化器 (EndpointPolicyScanInitializer.rescan) 启动时亦会整域清理, 显式迁移仅保证
--   存量库在启动前即无 internal 残留行。

-- 1. 清理 internal 域全部准入行 (含 coded 扫描行与历史/override 残留), 幂等
DELETE FROM `iam_endpoint_policy`
WHERE `domain` = 'internal';