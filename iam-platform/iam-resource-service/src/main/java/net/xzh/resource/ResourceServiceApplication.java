package net.xzh.resource;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 资源服务启动类.
 * <p>
 * 职责: 校验第三方传过来的 Bearer Token (通过授权服务器 /oauth2/introspect),
 * 并基于 token 中携带的 {@code sub} (用户名) 对外提供受权限保护的 API.
 */
@SpringBootApplication
public class ResourceServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServiceApplication.class, args);
    }
}