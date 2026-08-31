-- ============================================================
-- V6.7 迁移 - 认证中心新增 iam_external_identity (外部身份绑定表)
-- 说明: 对接微信 / 企业微信 / 钉钉 / 支付宝 / 谷歌 / GitHub 等第三方身份
--       同一第三方唯一标识 (provider + provider_open_id) 至多绑定一个本地用户
-- 归属: iam_identity 库 / iam-authorization-server
-- 备注: 仅建表, 绑定/解绑逻辑与登录链路后续版本接入
-- ============================================================

USE iam_identity;

CREATE TABLE IF NOT EXISTS `iam_external_identity`  (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `user_code` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '本地业务用户编码 (关联 sys_user.user_code)',
  `provider` varchar(30) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '第三方身份提供商: wechat=微信, wecom=企业微信, dingtalk=钉钉, alipay=支付宝, google=谷歌, github=GitHub',
  `provider_open_id` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT '第三方唯一标识 (openid/sub/登录标识)',
  `union_id` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方开放平台统一标识 (unionid, 微信系等多端通用; 无则空)',
  `nickname` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方昵称 (仅展示, 不覆盖本地昵称)',
  `avatar` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NULL DEFAULT NULL COMMENT '第三方头像 URL (仅展示, 不覆盖本地头像)',
  `status` tinyint(1) NOT NULL DEFAULT 1 COMMENT '绑定状态: 1=已绑定有效, 0=已解绑',
  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '首次绑定时间',
  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE INDEX `uk_provider_open_id`(`provider`, `provider_open_id`),
  INDEX `idx_user_code`(`user_code`)
) ENGINE = InnoDB DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = '外部身份绑定表 (第三方身份 ↔ 本地用户)';
