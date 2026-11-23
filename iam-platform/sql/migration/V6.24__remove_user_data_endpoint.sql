-- V6.24 迁移 - A-P2-7: 删除无调用方的级联清理接口 /admin/users/{userCode}/data
-- 背景: AdminUserDataController 零调用方 (前端/跨服务均无人调; 用户删除时的级联清理
--       已本地化到 UserService.deleteUser), 控制器已随本次提交删除。
-- 连动: 若不同步删 iam_endpoint 行, 启动漂移告警会将其报为幽灵行 (有表行无处理器)。
-- 影响: iam_endpoint_permission 的 (endpoint, record:read) 绑定随端点行一并删除;
--       权限码 record:read 本身保留 (仍绑 endpoint 47/48 + role 1 + scope 1)。

DELETE FROM `iam_endpoint_permission`
WHERE `endpoint_id` IN (
  SELECT `id` FROM `iam_endpoint`
  WHERE `method` = 'DELETE' AND `path` = '/admin/users/{userCode}/data'
);

DELETE FROM `iam_endpoint`
WHERE `method` = 'DELETE' AND `path` = '/admin/users/{userCode}/data';
