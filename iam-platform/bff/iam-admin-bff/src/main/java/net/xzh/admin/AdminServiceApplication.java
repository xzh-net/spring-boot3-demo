package net.xzh.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 管理后台服务启动类.
 * <p>
 * iam-admin-bff (8085): OAuth2 Client, 以授权码模式登录认证中心,
 * 将管理后台页面调用的 /admin/** 请求以用户 Bearer Token 代理转发到
 * 后端代理统一发往单服务 (9000), 由对端按令牌类别 (ADMIN_SERVICE_TOKEN 等) 校验权限。
 */
@SpringBootApplication
public class AdminServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AdminServiceApplication.class, args);
    }
}