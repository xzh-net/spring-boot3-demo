package net.xzh.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 管理后台服务启动类.
 * <p>
 * iam-admin-service (8085): OAuth2 Client, 以授权码模式登录认证中心,
 * 将管理后台页面调用的 /api/** 请求以用户 Bearer Token 代理转发到
 * 认证中心 (9000) / 资源中心 (9010), 由对端校验管理服务凭证 (ADMIN_SERVICE_TOKEN) 权限。
 */
@SpringBootApplication
public class AdminServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdminServiceApplication.class, args);
    }
}