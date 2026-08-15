package net.xzh.resource.config;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * V6.2 影子用户表迁移初始化器 (幂等).
 * <p>
 * 改造清单缺陷2: 删除资源中心影子用户表 sys_user, 角色关联改按业务用户编码 user_code.
 * 对旧库 (sys_user_role 仍为 user_id 外键) 执行迁移:
 * <ol>
 *   <li>跨库从认证中心 {@code iam_identity.sys_user} 按 user_id 回填 user_code;</li>
 *   <li>删除无可回填的孤儿关联, 将 user_id 列改为 user_code 并建唯一索引;</li>
 *   <li>删除影子用户表 sys_user。</li>
 * </ol>
 * 新库 (iam_authorization.sql V6.2) 直接使用 user_code, 本初始化器自动跳过。
 */
@Slf4j
@Order(0)
@Component
public class ShadowUserMigrationInitializer implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public ShadowUserMigrationInitializer(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            Boolean hasUserIdCol = jdbcTemplate.queryForObject(
                    "SELECT COUNT(1) FROM information_schema.columns " +
                            "WHERE table_schema = DATABASE() AND table_name = 'sys_user_role' AND column_name = 'user_id'",
                    Integer.class) > 0;
            if (hasUserIdCol != null && hasUserIdCol) {
                log.info("[ShadowUserMigration] 检测到影子用户表结构 (sys_user_role.user_id), 开始迁移...");
                jdbcTemplate.execute("ALTER TABLE sys_user_role ADD COLUMN user_code varchar(64) NULL AFTER role_id");

                // 跨库回填: user_id → iam_identity.sys_user.user_code
                int backfilled = jdbcTemplate.update(
                        "UPDATE sys_user_role ur JOIN iam_identity.sys_user u ON u.id = ur.user_id " +
                                "SET ur.user_code = u.user_code");
                log.info("[ShadowUserMigration] 回填 user_code: {} 行", backfilled);

                // 清理无法回填的孤儿关联, 升级列并建唯一索引 (DROP user_id 会连带删除旧唯一索引)
                int cleaned = jdbcTemplate.update(
                        "DELETE FROM sys_user_role WHERE user_code IS NULL OR user_code = ''");
                log.info("[ShadowUserMigration] 清理孤儿关联: {} 行", cleaned);
                jdbcTemplate.execute(
                        "ALTER TABLE sys_user_role DROP COLUMN user_id, " +
                                "MODIFY user_code varchar(64) NOT NULL, " +
                                "ADD UNIQUE INDEX uk_user_code_role(user_code, role_id)");

                // 删除影子用户表
                jdbcTemplate.execute("DROP TABLE IF EXISTS sys_user");
                log.info("[ShadowUserMigration] 影子用户表 sys_user 已删除, 迁移完成");
            } else {
                log.info("[ShadowUserMigration] sys_user_role 已是 user_code 结构, 跳过迁移");
            }

            // 幂等自愈: 旧版启动库曾在 sys_user_role 上建过单列唯一索引 uk_user_role(role_id),
            // 该索引会阻止多用户绑定同一角色 (Duplicate entry ... for key 'sys_user_role.uk_user_role')。
            // DROP COLUMN user_id 不会删除它, 故这里检测并清理, 以 (user_code, role_id) 复合唯一索引为准。
            cleanupLegacyRoleIndex();
        } catch (Exception e) {
            log.error("[ShadowUserMigration] 迁移失败: {}", e.getMessage(), e);
        }
    }

    /**
     * 清理历史遗留的单列唯一索引 uk_user_role(role_id) (幂等).
     */
    private void cleanupLegacyRoleIndex() {
        try {
            String idxCols = jdbcTemplate.queryForObject(
                    "SELECT GROUP_CONCAT(column_name ORDER BY seq_in_index) FROM information_schema.statistics " +
                            "WHERE table_schema = DATABASE() AND table_name = 'sys_user_role' AND index_name = 'uk_user_role'",
                    String.class);
            if (idxCols != null && idxCols.equalsIgnoreCase("role_id")) {
                jdbcTemplate.execute("ALTER TABLE sys_user_role DROP INDEX uk_user_role");
                log.info("[ShadowUserMigration] 已清理遗留单列唯一索引 uk_user_role(role_id)");
            }
        } catch (Exception e) {
            log.warn("[ShadowUserMigration] 清理遗留索引失败: {}", e.getMessage());
        }
    }
}