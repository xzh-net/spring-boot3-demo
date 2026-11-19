-- V6.21 迁移 - 标准协议 scope 入字典: openid / profile / email 登记进 sys_scope
--
-- 背景: 客户端管理页授权范围勾选原为「字典组 + 前端硬编码标准 scope」两套来源,
--       裁定统一为字典驱动 (勾选什么就是什么, 与业务范围组不区分)。
--       标准 scope 有真实协议作用 (openid=签发 id_token / profile·email=/userinfo 字段),
--       故入字典作为种子; read·write 为纯占位, 不入字典 (存量客户端注册值保留, 页面动态补框)。
--
-- 语义影响评估: 三行均无 sys_scope_permission 映射 → 展开为空,
--       resolveClientBusinessCodes / expandScopeCodes 业务码结果不变 (fail-closed 空集路径不变)。
--       附带: 权限管理页「所属授权范围」可选范围 +3 (可把权限码映射进标准组, 与 third.profile 同性质)。
--
-- remark 约定: 可写谁持有, 不写数量。
-- 一次性 DDL/DML 不可重复执行; 新库走基线 iam.sql 同构。

-- ============ 1. 标准协议 scope 三行 (id 4/5/6, 无映射) ============
INSERT INTO `sys_scope` (id, code, name, status, remark) VALUES
(4, 'openid',  '身份认证', 1, 'OIDC 标准 scope: 签发 id_token 的依据 (各客户端持有)'),
(5, 'profile', '基本资料', 1, 'OIDC 标准 scope: /userinfo 返回昵称/头像 (各客户端持有)'),
(6, 'email',   '电子邮箱', 1, 'OIDC 标准 scope: /userinfo 返回邮箱 (除 admin-app 外均持有)');

-- ============ 2. 存量 remark 去数量 (裁定: 可写谁持有, 不写数量) ============
UPDATE `sys_scope`
   SET `remark` = '管理后台应用: 全部 admin 域业务码 (admin-app 持有)'
 WHERE `code` = 'admin.full';

UPDATE `sys_scope`
   SET `remark` = '三方/外部客户端: 三方域暂无端点, 空映射 fail-closed (oa-web-app / oa-h5-app 持有, 仅 OIDC 标准能力)'
 WHERE `code` = 'third.profile';

-- ============ 3. 核对 (期望: 6 行; openid/profile/email 映射数 = 0) ============
SELECT COUNT(*) AS scopes FROM `sys_scope`;
SELECT s.code, COUNT(b.id) AS mappings
  FROM `sys_scope` s LEFT JOIN `sys_scope_permission` b ON b.scope_id = s.id
 WHERE s.code IN ('openid', 'profile', 'email')
 GROUP BY s.code;
