-- V6.15 迁移 - 新增登录准入表 client_login_policy (登录维度独立于授权维度)
--
-- 背景: 签发准入原以「用户 RBAC 码 ∩ 客户端 scope 展开码」交集判定 (IssuanceAdmissionService),
--       登录资格与接口权限耦合于同一组权限码 — 改权限即改登录边界 (D1), scope 展开为空时
--       逃逸阀放行 (D2 失败方向反), 且规则无页面可查 (D3)。本次将登录维度拆出为独立 allow-list 表,
--       交集退回授权层专司「令牌业务码封顶」(OAuth2 scope 语义), 两层解耦。
--
-- 变更内容:
--   1) 新建 client_login_policy (client_id + subject_type/subject_id + status),
--      无外键 (逻辑引用 oauth2_registered_client.client_id, 与 sso_client_id 同风格)。
--   2) 种子 6 行: admin-app←ROLE ADMIN / portal-app←ROLE PORTAL /
--      device-app←ROLE THIRD_PARTY (设备码客户端收敛为三方角色, 不再对所有用户开放) /
--      oa-web-app / oa-h5-app / mobile-app←ANY。
--
-- 关键注记:
--   - fail-closed 方向修正: 无启用行 = 拒绝 (原逃逸阀对空 scope 放行, 已随
--     IssuanceAdmissionService 移除, 逃逸语义改由显式 ANY 行表达)。
--   - 授权层不变: 令牌业务码仍 = 用户码 ∩ scope码 (RbacAuthoritiesOpaqueTokenIntrospector),
--     本表不参与自省裁决。
--   - 服务端判定 LoginAdmissionService.canLogin 已就位, 但 AuthorizeIssuanceFilter
--     AuthorizeIssuanceFilter 按准入表实时裁决 (已启用), 未命中 302 拒发码 fail-closed。
--   - 管理 API/页面写入口未建 (评估后补); 届时需同步 iam_endpoint_policy 种子行。
--   - 一次性 DDL, 不可重复执行 (新库走基线 iam.sql, 无需本脚本)。

-- ============ 1. 新建登录准入表 ============
CREATE TABLE `client_login_policy`  (
  `id` bigint(0) NOT NULL AUTO_INCREMENT COMMENT '准入ID',
  `client_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'OAuth2 client_id (逻辑引用 oauth2_registered_client.client_id, 无外键)',
  `subject_type` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '主体类型: ROLE=角色 / USER=用户 / ANY=所有已登录用户',
  `subject_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT '' COMMENT '主体ID: ROLE=sys_role.code / USER=user_code / ANY=空串',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '状态: 1=启用, 0=停用 (停用行不参与判定)',
  `remark` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '备注',
  `create_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) COMMENT '创建时间',
  `update_time` datetime(0) NOT NULL DEFAULT CURRENT_TIMESTAMP(0) ON UPDATE CURRENT_TIMESTAMP(0) COMMENT '更新时间',
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `uk_policy`(`client_id`, `subject_type`, `subject_id`) USING BTREE
) ENGINE = InnoDB CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '客户端登录准入表 (登录维度: 谁能登录该客户端; allow-list, fail-closed)' ROW_FORMAT = Dynamic;

-- ============ 2. 种子 (device-app 收敛为仅 THIRD_PARTY, 其余与原签发准入放行结果一致) ============
INSERT INTO `client_login_policy` (`client_id`, `subject_type`, `subject_id`, `status`, `remark`) VALUES
('admin-app',   'ROLE', 'ADMIN',  1, '管理后台: 仅 ADMIN 角色 (原交集: ADMIN 16码 ∩ admin.full 16码)'),
('portal-app',  'ROLE', 'PORTAL', 1, '门户 SSO: 仅 PORTAL 角色 (原交集: PORTAL 1码 ∩ portal.profile 1码)'),
('oa-web-app',  'ANY',  '',       1, '三方 Web 演示: 所有登录用户 (原逃逸阀: third.profile 空映射)'),
('oa-h5-app',   'ANY',  '',       1, 'OA H5 演示: 所有登录用户 (原逃逸阀: third.profile 空映射)'),
('device-app',  'ROLE', 'THIRD_PARTY', 1, '设备码客户端: 仅 THIRD_PARTY 角色 (设备/IoT/CLI 三方演示)'),
('mobile-app',  'ANY',  '',       1, '移动原生演示: 所有登录用户 (原逃逸阀: 无业务 scope)');

-- ============ 3. 端点准入行 (管理 API, 否则启动扫描落 AUTHENTICATED 宽松档) ============
-- ON DUPLICATE KEY: 兼容「扫描已先以 AUTHENTICATED 播种」的情况, 用精确码覆盖宽松档。
INSERT INTO `iam_endpoint_policy` (`method`, `path`, `required_authority`, `status`) VALUES
('GET', '/admin/login-policies', 'client:read', 1),
('GET', '/admin/login-policies/{clientId}', 'client:read', 1),
('PUT', '/admin/login-policies/{clientId}', 'client:write', 1)
ON DUPLICATE KEY UPDATE `required_authority` = VALUES(`required_authority`), `status` = VALUES(`status`);
