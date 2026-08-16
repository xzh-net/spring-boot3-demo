package net.xzh.authserver.config;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * V6.4 租户成员关系编码化迁移初始化器 (幂等).
 * <p>
 * iam_tenant_user 下放引用改用业务编码 (tenant_code / user_code), 不再引用内部自增主键,
 * 与 sys_user.user_code / iam_tenant.tenant_code 的"离开认证库用编码"原则一致。
 * 对旧库 (iam_tenant_user 仍为 tenant_id + user_id) 执行迁移:
 * <ol>
 *   <li>新增 tenant_code / user_code 两列, 跨表按 id 回填编码;</li>
 *   <li>删除无法回填的孤儿关联, 移除列并重建唯一索引;</li>
 *   <li>新库 (iam_identity.sql V6.4) 直接使用编码结构, 自动跳过。</li>
 * </ol>
 */
@Slf4j
@Order(10)
@Component
public class TenantUserMigrationInitializer implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    public TenantUserMigrationInitializer(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            Boolean hasOldStructure = jdbcTemplate.queryForObject(
                    "SELECT COUNT(1) FROM information_schema.columns " +
                            "WHERE table_schema = DATABASE() AND table_name = 'iam_tenant_user' AND column_name = 'tenant_id'",
                    Integer.class) > 0;
            if (!Boolean.TRUE.equals(hasOldStructure)) {
                log.info("[TenantUserMigration] iam_tenant_user 已是编码结构, 跳过迁移");
                return;
            }
            log.info("[TenantUserMigration] 检测到 iam_tenant_user 旧结构 (tenant_id/user_id), 开始迁移...");
            jdbcTemplate.execute("ALTER TABLE iam_tenant_user " +
                    "ADD COLUMN tenant_code varchar(64) NULL, " +
                    "ADD COLUMN user_code varchar(64) NULL");

            int tenantBackfilled = jdbcTemplate.update(
                    "UPDATE iam_tenant_user tu JOIN iam_tenant t ON t.id = tu.tenant_id " +
                            "SET tu.tenant_code = t.tenant_code");
            int userBackfilled = jdbcTemplate.update(
                    "UPDATE iam_tenant_user tu JOIN sys_user u ON u.id = tu.user_id " +
                            "SET tu.user_code = u.user_code");
            log.info("[TenantUserMigration] 回填 tenant_code: {} 行, user_code: {} 行",
                    tenantBackfilled, userBackfilled);

            int cleaned = jdbcTemplate.update(
                    "DELETE FROM iam_tenant_user WHERE tenant_code IS NULL OR tenant_code = '' " +
                            "OR user_code IS NULL OR user_code = ''");
            log.info("[TenantUserMigration] 清理孤儿关联: {} 行", cleaned);

            // DROP tenant_id/user_id 会连带删除其上的索引 (uk_tenant_user / idx_user), 随后重建编码索引
            jdbcTemplate.execute("ALTER TABLE iam_tenant_user " +
                    "DROP COLUMN tenant_id, DROP COLUMN user_id, " +
                    "MODIFY tenant_code varchar(64) NOT NULL, MODIFY user_code varchar(64) NOT NULL, " +
                    "ADD UNIQUE INDEX uk_tenant_user(tenant_code, user_code), " +
                    "ADD INDEX idx_user_code(user_code)");
            log.info("[TenantUserMigration] iam_tenant_user 编码化迁移完成");
        } catch (Exception e) {
            log.error("[TenantUserMigration] 迁移失败: {}", e.getMessage(), e);
        }
    }
}