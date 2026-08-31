package net.xzh.iam.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * 身份管理面 (iam-identity-service).
 * <p>
 * 定位: 管理面服务, <b>无数据库</b> —— 用户/租户/客户端/会话等身份数据的单一写者
 * 是认证中心 (iam-auth-server) 运行时, 本服务只经其内部 API ({@code /api/internal/identity/**})
 * 写入; 跨域编排 (删用户联动清理权限中心 RBAC) 也在此收口。
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
