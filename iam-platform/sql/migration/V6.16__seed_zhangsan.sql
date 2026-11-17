-- V6.16 迁移 - 种子用户 zhangsan (THIRD_PARTY) 补执行到存量库
--
-- 背景: 3c945a3 已把 zhangsan 写入基线种子 sql/iam.sql (sys_user 第 3 行 +
--       sys_user_role 绑定 THIRD_PARTY), 但按团队规范迁移为「手动逐版本执行」,
--       当时仅改种子未新开 migration 脚本 —— 存量库缺该用户, 设备码放行路径
--       (device-app 准入收敛为仅 THIRD_PARTY) 在存量库上只能依赖运行时账号 zhang3。
--
-- 变更内容:
--   1) sys_user 幂等插入 zhangsan (user_code=550e8400-e29b-41d4-a716-446655440003,
--      与 admin/user 同款 BCrypt hash, 密码 123456, 角色 THIRD_PARTY 所需凭据)
--   2) sys_user_role 幂等绑定 THIRD_PARTY (按 sys_role.code 反查 id, 不写死角色主键)
--
-- 关键注记:
--   - 幂等可重复执行 (WHERE NOT EXISTS): 新库走基线 iam.sql 已含 zhangsan, 本脚本自动跳过;
--   - 不写死自增主键 (历史库 id 序列不一, id 仅内部联表, 对外只认 user_code);
--   - 不删除历史运行时账号 zhang3 (非破坏原则; reset-init 重载后自然消失);
--   - 需与基线 iam.sql 保持同值: hash/编码/昵称 任一变更须两处同步。
--
-- ============ 1. 种子用户 zhangsan ============
INSERT INTO `sys_user` (`user_code`, `username`, `password`, `nickname`, `email`, `phone`, `avatar`, `enabled`, `account_non_expired`, `account_non_locked`, `credentials_non_expired`, `create_time`, `update_time`)
SELECT '550e8400-e29b-41d4-a716-446655440003', 'zhangsan', '$2a$10$ov3NUrdkAHujSRdGbDZF6O9h2cjZq4Zl17fL3TA5Nhs94mE/PmH8e', '张三', 'zhangsan@example.com', NULL, NULL, 1, 1, 1, 1, '2026-08-11 20:00:08', '2026-08-11 20:00:08'
WHERE NOT EXISTS (
    SELECT 1 FROM `sys_user` WHERE `username` = 'zhangsan' OR `user_code` = '550e8400-e29b-41d4-a716-446655440003'
);

-- ============ 2. 绑定 THIRD_PARTY 角色 (device-app 准入放行所需) ============
INSERT INTO `sys_user_role` (`user_code`, `role_id`)
SELECT '550e8400-e29b-41d4-a716-446655440003', `r`.`id`
FROM `sys_role` `r`
WHERE `r`.`code` = 'THIRD_PARTY'
  AND NOT EXISTS (
      SELECT 1 FROM `sys_user_role` `ur`
      WHERE `ur`.`user_code` = '550e8400-e29b-41d4-a716-446655440003'
        AND `ur`.`role_id` = `r`.`id`
  );
