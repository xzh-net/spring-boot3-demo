-- V6.22 迁移 - 清除占位 scope: read/write 退出客户端注册表
--
-- 背景: read/write 为历史占位, 全链零消费方 (sys_scope 字典无 → 展开为空;
--       /userinfo switch 落 default 跳过; Java 代码字面量 0 命中)。
--       判据 = 「无消费方」而非「属原 scope」; openid/profile/email 有协议消费方 (id_token /
--       /userinfo) 保留。
--
-- 顺序依赖 (2026-11-19 已先改请求方, 再清本表, 否则 invalid_scope 断演示):
--   1) device-demo SCOPE        'openid profile email read'  → 'openid profile email'
--   2) web-demo    authorize    'openid profile email read write' → 'openid profile email'
--   3) h5-demo     SCOPES       'openid profile email read write' → 'openid profile email'
--   4) 本迁移清 5 行注册值 + 基线 iam.sql 同步 (同构)
--
-- 语义影响: 业务码零变化 (read/write 从未在 sys_scope, 展开本就为空);
--          RFC 7662 scope claim (P0-1 已改读注册表) 不再捎带 read/write。
-- 一次性 DML 不可重复执行; 新库走基线 iam.sql。

-- ============ 1. 五个客户端注册 scope 去 read/write ============
UPDATE `oauth2_registered_client`
   SET `scopes` = 'openid,profile,admin.full'
 WHERE `client_id` = 'admin-app';

UPDATE `oauth2_registered_client`
   SET `scopes` = 'openid,profile,email,third.profile'
 WHERE `client_id` IN ('oa-web-app', 'oa-h5-app');

UPDATE `oauth2_registered_client`
   SET `scopes` = 'openid,profile,email'
 WHERE `client_id` IN ('device-app', 'mobile-app');

-- ============ 2. 核对 (期望: 全库 active 行 0 个 read/write) ============
SELECT `client_id`, `scopes` FROM `oauth2_registered_client` ORDER BY `id`;
SELECT COUNT(*) AS remaining_read_write
  FROM `oauth2_registered_client`
 WHERE `scopes` LIKE '%read%' OR `scopes` LIKE '%write%';
