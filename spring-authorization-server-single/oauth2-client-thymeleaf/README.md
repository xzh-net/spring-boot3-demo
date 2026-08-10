# OAuth2 Thymeleaf 客户端示例

非前后端分离 Spring Boot 3 OAuth2 客户端示例，演示传统 SSR Web 应用如何通过 Spring Security 6 OAuth2 Client 对接 `spring-authorization-server`。

## 场景定位

| 维度 | 说明 |
|---|---|
| 应用类型 | 传统 SSR Web 应用 (Thymeleaf 服务端渲染) |
| 客户端 | `web-app` (Confidential Client) |
| 认证方式 | `client_secret_basic` |
| 授权模式 | `authorization_code` |
| 自身登录页 | ❌ 无，完全委托授权服务器完成身份认证 |
| OIDC 登出 | ✅ 通过 RP-Initiated Logout 协议同步登出 |

## 端口与对接

| 项目 | 端口 |
|---|---|
| 授权服务器 (`spring-authorization-server`) | 9000 |
| 本客户端 (`oauth2-client-thymeleaf`) | 8083 |
| Node.js 演示 (`oauth2-callback-web-app`) | 8080 |

> 三个端口互不冲突，可同时运行。

## 文件结构

```
oauth2-client-thymeleaf/
├── pom.xml                                           # Boot 3.4.1 + oauth2-client + thymeleaf
└── src/main/
    ├── java/net/xzh/client/
    │   ├── ClientApplication.java                    # 主启动类
    │   ├── config/SecurityConfig.java               # SSO + OIDC Logout 配置 (核心)
    │   └── web/DefaultController.java                # 首页与登出页控制器
    └── resources/
        ├── application.yml                           # OAuth2 Client registration (对接 web-app)
        └── templates/
            ├── index.html                            # 首页 (展示已登录用户 + ID Token Claims)
            └── logged-out.html                      # 登出页
```

## 启动步骤

### 1. 启动授权服务器

参考主项目根 README，确保 `spring-authorization-server` 在 9000 端口运行。

### 2. 启动本客户端

```bash
cd oauth2-client-thymeleaf
mvn spring-boot:run
```

### 3. 访问

- 首页：http://localhost:8083/
- 浏览器访问后会自动重定向到授权服务器完成登录
- 默认账号：`user / 123456`
- 登录成功后回到首页，展示用户信息与 ID Token 声明
- 点击右上角"退出登录"会同步登出授权服务器端会话

## 核心配置说明

### SecurityConfig.java

```java
http
    .authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/webjars/**", "/assets/**", "/logged-out", "/favicon.ico").permitAll()
        .anyRequest().authenticated())
    .oauth2Login(oauth2Login -> oauth2Login
        .loginPage("/oauth2/authorization/web-app-oidc"))
    .logout(logout -> logout
        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
```

- `oauth2Login` 未认证请求被自动重定向到授权服务器 `/oauth2/authorize`
- `OidcClientInitiatedLogoutSuccessHandler` 携带 `id_token_hint` 跳转授权服务器 `end_session_endpoint`，实现 SSO 单点登出

### application.yml

```yaml
spring.security.oauth2.client.registration.web-app-oidc:
  client-id: web-app
  client-secret: 123456
  authorization-grant-type: authorization_code
  scope: openid, profile, email
```

## 与 Node.js 演示 (`oauth2-callback-web-app`) 的区别

| 维度 | Node.js 演示 | 本 Thymeleaf 客户端 |
|---|---|---|
| 技术栈 | Node.js + 原生 http | Spring Boot 3.4.1 + Thymeleaf |
| OAuth2 流程 | 手写 code 交换 | Spring Security 6 自动处理 |
| Session 管理 | 手写 cookie + state | Spring Session 自动管理 |
| 适用场景 | 验证协议细节、调试 | 真实 SSR 项目接入参考 |
| OIDC 登出 | ❌ 未实现 | ✅ RP-Initiated Logout |

## 参考

代码改造自 [D:/GitHub/spring-boot3-demo/spring-authorization-server/spring-authorization-client](../../../../spring-authorization-server/spring-authorization-client) (Spring 官方示例 by Joe Grandja)，
裁剪掉 mTLS / token_exchange / device_code 等演示场景，只保留 authorization_code + client_secret 一种核心流程。
