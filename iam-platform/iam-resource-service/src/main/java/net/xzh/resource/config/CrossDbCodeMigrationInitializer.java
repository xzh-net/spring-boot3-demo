package net.xzh.resource.config;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * V6.4 编码化引用迁移初始化器 (幂等).
 * <p>
 * 「离开认证库用编码」原则落地, 资源中心业务库不再存认证中心内部自增主键 id:
 * <ol>
 *   <li>iam_application / iam_org / iam_app_authorization 的 tenant_id 改为 tenant_code
 *       (跨库从 iam_identity.iam_tenant 按 id 回填编码);</li>
 *   <li>iam_app_authorization 的 ROLE 主体 subject_id 由 sys_role.id 统一为角色编码 sys_role.code,
 *       ORG 主体由 iam_org.id 统一为组织编码 iam_org.org_code (与 USER=user_code 编码寻址一致)。</li>
 * </ol>
 * 新库 (iam_authorization.sql V6.4) 直接为编码结构, 本初始化器自动跳过。
 */
@Slf4j
@Order(1)
@Component
public class CrossDbCodeMigrationInitializer implements ApplicationRunner {

    private static final String CHK = "SELECT COUNT(1) FROM information_schema.columns " +
            "WHERE table_schema = DATABASE() AND table_name = '%s' AND column_name = '%s'";

    private final JdbcTemplate jdbcTemplate;

    public CrossDbCodeMigrationInitializer(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            migrateApplicationTenant();
            migrateOrgTenant();
            migrateAuthorization();
            log.info("[CrossDbCodeMigration] 编码化引用迁移扫描完成");
        } catch (Exception e) {
            log.error("[CrossDbCodeMigration] 迁移失败: {}", e.getMessage(), e);
        }
    }

    private boolean hasColumn(String table, String column) {
        Integer count = jdbcTemplate.queryForObject(String.format(CHK, table, column), Integer.class);
        return count != null && count > 0;
    }

    /** iam_application.tenant_id → tenant_code */
    private void migrateApplicationTenant() {
        if (!hasColumn("iam_application", "tenant_id")) {
            return;
        }
        log.info("[CrossDbCodeMigration] iam_application 迁移 tenant_id → tenant_code ...");
        jdbcTemplate.execute("ALTER TABLE iam_application ADD COLUMN tenant_code varchar(64) NULL");
        jdbcTemplate.update(
                "UPDATE iam_application a LEFT JOIN iam_identity.iam_tenant t ON t.id = a.tenant_id " +
                        "SET a.tenant_code = t.tenant_code");
        jdbcTemplate.update("UPDATE iam_application SET tenant_code = 'T001' WHERE tenant_code IS NULL OR tenant_code = ''");
        jdbcTemplate.execute("ALTER TABLE iam_application DROP COLUMN tenant_id, " +
                "MODIFY tenant_code varchar(64) NOT NULL");
        log.info("[CrossDbCodeMigration] iam_application 迁移完成");
    }

    /** iam_org.tenant_id → tenant_code */
    private void migrateOrgTenant() {
        if (!hasColumn("iam_org", "tenant_id")) {
            return;
        }
        log.info("[CrossDbCodeMigration] iam_org 迁移 tenant_id → tenant_code ...");
        jdbcTemplate.execute("ALTER TABLE iam_org ADD COLUMN tenant_code varchar(64) NULL");
        jdbcTemplate.update(
                "UPDATE iam_org o LEFT JOIN iam_identity.iam_tenant t ON t.id = o.tenant_id " +
                        "SET o.tenant_code = t.tenant_code");
        jdbcTemplate.update("UPDATE iam_org SET tenant_code = 'T001' WHERE tenant_code IS NULL OR tenant_code = ''");
        jdbcTemplate.execute("ALTER TABLE iam_org DROP COLUMN tenant_id, MODIFY tenant_code varchar(64) NOT NULL");
        log.info("[CrossDbCodeMigration] iam_org 迁移完成");
    }

    /** iam_app_authorization: tenant_id → tenant_code + ROLE/ORG 主体编码化 */
    private void migrateAuthorization() {
        boolean needsTenant = hasColumn("iam_app_authorization", "tenant_id");
        // 主体编码化与 tenant 迁移相互独立, 分别判定
        boolean needsSubject = jdbcTemplate.queryForObject(
                "SELECT COUNT(1) FROM iam_app_authorization WHERE subject_type IN ('ROLE','ORG') " +
                        "AND subject_id REGEXP '^[0-9]+$'",
                Integer.class) > 0;

        if (!needsTenant && !needsSubject) {
            return;
        }
        log.info("[CrossDbCodeMigration] iam_app_authorization 迁移 tenant_id → tenant_code, 主体编码化 ...");

        // 主体编码化 (先于 index 重建, 不依赖表结构变化)
        if (needsSubject) {
            int roles = jdbcTemplate.update(
                    "UPDATE iam_app_authorization a JOIN sys_role r ON a.subject_id = CAST(r.id AS CHAR) " +
                            "SET a.subject_id = r.code WHERE a.subject_type = 'ROLE'");
            int orgs = jdbcTemplate.update(
                    "UPDATE iam_app_authorization a JOIN iam_org o ON a.subject_id = CAST(o.id AS CHAR) " +
                            "SET a.subject_id = o.org_code WHERE a.subject_type = 'ORG'");
            int cleaned = jdbcTemplate.update(
                    "DELETE FROM iam_app_authorization WHERE " +
                            "(subject_type = 'ROLE' AND NOT EXISTS (SELECT 1 FROM sys_role r WHERE r.code = subject_id)) OR " +
                            "(subject_type = 'ORG' AND NOT EXISTS (SELECT 1 FROM iam_org o WHERE o.org_code = subject_id))");
            log.info("[CrossDbCodeMigration] 主体编码化: ROLE→{} 行, ORG→{} 行, 清理孤儿 {} 行",
                    roles, orgs, cleaned);
        }

        // tenant_id → tenant_code (先移除旧唯一索引, 避免 DROP 列连带删除)
        if (needsTenant) {
            jdbcTemplate.execute("ALTER TABLE iam_app_authorization DROP INDEX uk_authz, " +
                    "ADD COLUMN tenant_code varchar(64) NULL");
            jdbcTemplate.update(
                    "UPDATE iam_app_authorization a LEFT JOIN iam_identity.iam_tenant t ON t.id = a.tenant_id " +
                            "SET a.tenant_code = t.tenant_code");
            jdbcTemplate.update("UPDATE iam_app_authorization SET tenant_code = 'T001' " +
                    "WHERE tenant_code IS NULL OR tenant_code = ''");
            jdbcTemplate.execute("ALTER TABLE iam_app_authorization DROP COLUMN tenant_id, " +
                    "MODIFY tenant_code varchar(64) NOT NULL, " +
                    "ADD UNIQUE INDEX uk_authz(tenant_code, app_id, channel_id, subject_type, subject_id)");
        }
        log.info("[CrossDbCodeMigration] iam_app_authorization 迁移完成");
    }
}