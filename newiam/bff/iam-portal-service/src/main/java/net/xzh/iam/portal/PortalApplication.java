package net.xzh.iam.portal;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 门户应用启动类.
 * <p>
 * 独立的 OAuth2 客户端, 通过授权码模式对接认证中心 (http://localhost:9000)。
 * 前后端不分离: Thymeleaf 服务端渲染 + 静态资源。
 */
@SpringBootApplication
public class PortalApplication {

    public static void main(String[] args) {
        SpringApplication.run(PortalApplication.class, args);
    }
}
