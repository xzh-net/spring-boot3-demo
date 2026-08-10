package net.xzh.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 非前后端分离 Spring Boot OAuth2 客户端示例。
 *
 * <p>对接 spring-authorization-server-single (端口 9000) 中的 web-app 客户端，
 * 使用 authorization_code + client_secret_basic 完成用户登录，登录后展示用户信息，
 * 支持通过 OIDC RP-Initiated Logout 协议向授权服务器发起登出。</p>
 *
 * <p>场景定位：传统 SSR Web 应用 (Thymeleaf 服务端渲染)，自身无登录页，
 * 完全委托授权服务器完成身份认证。</p>
 *
 * @author xzh
 */
@SpringBootApplication
public class ClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
    }
}
