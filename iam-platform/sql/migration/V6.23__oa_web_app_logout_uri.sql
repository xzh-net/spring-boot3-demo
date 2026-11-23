-- ============================================================
-- V6.23 迁移 - oa-web-app 补登记登出跳转地址 http://localhost:8081/
-- 背景: A-P1-6 —— 登出跳转改为「必须逐字匹配注册客户端 post_logout_redirect_uris」
--       iam-client-web-demo (oa-web-app, 端口 8081) 的登出目标是其首页
--       http://localhost:8081/ , 而登记表只有 /logout, 不补登记会被新校验打落。
-- 归属: iam 库 / iam-authorization-server
-- 备注: 以 iam.sql (base) 为唯一来源; 本脚本供存量库手动执行 (幂等: NOT LIKE 防重复追加)。
-- ============================================================

USE iam;

UPDATE `oauth2_registered_client`
SET `post_logout_redirect_uris` = CONCAT(`post_logout_redirect_uris`, ',http://localhost:8081/')
WHERE `client_id` = 'oa-web-app'
  AND `post_logout_redirect_uris` <> 'http://localhost:8081/'
  AND `post_logout_redirect_uris` NOT LIKE '%,http://localhost:8081/';
