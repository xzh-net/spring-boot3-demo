package net.xzh.authserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * RBAC 表自愈初始化器.
 * <p>
 * 数据库若从旧版 schema.sql 初始化 (早于 RBAC 四表 sys_role / sys_user_role /
 * sys_permission / sys_role_permission 加入), 则资源服务 (iam-resource-service)
 * 按 sub 查询角色/权限时会报 Table 'xxx.sys_role' doesn't exist。
 * 本组件在启动时检测缺失的表并按需补建 + 写入种子数据 (幂等)。
 * </p>
 */
@Slf4j
@Component
@Order(20)
@RequiredArgsConstructor
public class RbacDataInitializer implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    public void run(ApplicationArguments args) {
        boolean hasSysRole = tableExists("sys_role");
        boolean hasSysUserRole = tableExists("sys_user_role");
        boolean hasSysPermission = tableExists("sys_permission");
        boolean hasSysRolePermission = tableExists("sys_role_permission");

        if (hasSysRole && hasSysUserRole && hasSysPermission && hasSysRolePermission) {
            return;
        }
        log.info("[RbacInit] 检测到 RBAC 表缺失 (sys_role={}, sys_user_role={}, sys_permission={}, sys_role_permission={}), 开始补建",
                hasSysRole, hasSysUserRole, hasSysPermission, hasSysRolePermission);

        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sys_role (
                    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '角色ID',
                    code        VARCHAR(50)  NOT NULL UNIQUE COMMENT '角色编码 (如 ADMIN / USER)',
                    name        VARCHAR(100) NOT NULL COMMENT '角色名称',
                    remark      VARCHAR(500) DEFAULT NULL COMMENT '备注',
                    create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
                    update_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色表';
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sys_user_role (
                    id      BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '关联ID',
                    user_id BIGINT NOT NULL COMMENT '用户ID (关联 sys_user.id)',
                    role_id BIGINT NOT NULL COMMENT '角色ID (关联 sys_role.id)',
                    UNIQUE KEY uk_user_role (user_id, role_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户-角色关联表';
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sys_permission (
                    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '权限ID',
                    code        VARCHAR(100) NOT NULL UNIQUE COMMENT '权限标识 (如 app:crm)',
                    name        VARCHAR(100) NOT NULL COMMENT '权限名称',
                    type        VARCHAR(30)  NOT NULL DEFAULT 'app' COMMENT '权限类型: app=应用访问',
                    remark      VARCHAR(500) DEFAULT NULL COMMENT '备注',
                    create_time DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='权限表';
                """);
        jdbcTemplate.execute("""
                CREATE TABLE IF NOT EXISTS sys_role_permission (
                    id            BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '关联ID',
                    role_id       BIGINT NOT NULL COMMENT '角色ID (关联 sys_role.id)',
                    permission_id BIGINT NOT NULL COMMENT '权限ID (关联 sys_permission.id)',
                    UNIQUE KEY uk_role_permission (role_id, permission_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='角色-权限关联表';
                """);

        // 种子数据 (幂等: id 冲突则忽略)
        jdbcTemplate.execute("""
                INSERT IGNORE INTO sys_role (id, code, name, remark) VALUES
                    (1, 'ADMIN', '管理员', '拥有全部应用访问权限'),
                    (2, 'USER', '普通用户', '仅可访问门户与 OA');
                """);
        jdbcTemplate.execute("""
                INSERT IGNORE INTO sys_permission (id, code, name, type, remark) VALUES
                    (1, 'app:portal', '门户应用', 'app', '统一工作台门户'),
                    (2, 'app:oa',     'OA 办公系统', 'app', '办公自动化'),
                    (3, 'app:crm',    'CRM 客户管理', 'app', '客户关系管理'),
                    (4, 'app:erp',    'ERP 企业资源', 'app', '企业资源计划'),
                    (5, 'app:bi',     'BI 数据分析', 'app', '商业智能分析');
                """);

        // 用户-角色 (依赖 sys_user 已存在: admin=1, user=2)
        Integer adminId = queryUserId("admin");
        Integer userId = queryUserId("user");
        if (adminId != null) {
            jdbcTemplate.update("INSERT IGNORE INTO sys_user_role (user_id, role_id) VALUES (?, 1)", adminId);
        }
        if (userId != null) {
            jdbcTemplate.update("INSERT IGNORE INTO sys_user_role (user_id, role_id) VALUES (?, 2)", userId);
        }

        // 角色-权限: ADMIN 拥有全部 5 个应用, USER 拥有门户 + OA
        for (int permId : List.of(1, 2, 3, 4, 5)) {
            jdbcTemplate.update("INSERT IGNORE INTO sys_role_permission (role_id, permission_id) VALUES (1, ?)", permId);
        }
        for (int permId : List.of(1, 2)) {
            jdbcTemplate.update("INSERT IGNORE INTO sys_role_permission (role_id, permission_id) VALUES (2, ?)", permId);
        }

        log.info("[RbacInit] RBAC 表补建完成, 种子数据已写入 (admin->ADMIN 全部应用, user->USER 门户+OA)");
    }

    private boolean tableExists(String table) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
                    Integer.class, table);
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private Integer queryUserId(String username) {
        try {
            return jdbcTemplate.queryForObject("SELECT id FROM sys_user WHERE username = ?", Integer.class, username);
        } catch (Exception e) {
            return null;
        }
    }
}