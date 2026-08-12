# Portal Server — 门户 BFF

门户后端服务（Backend For Frontend），作为 OAuth2 Client 与认证中心交互，为 portal-app 前端提供 REST API。

- 端口：`8080`
- 依赖：Spring Boot 3.x + Spring Security 6.4 + Spring Security OAuth2 Client
- 角色：**Confidential Client + PKCE**（持有 `portal-app` 的 `client_secret`）

## 架构定位

```
[浏览器] ──► portal-app (8000, 前端)
                 │
                 │  /api/* 代理（透传 Cookie）
                 ▼
             portal-server (8080, BFF)  ← 本模块
                 │
                 │  OAuth2 授权码 + PKCE（自定义 Resolver + TokenResponseClient）
                 ▼
             spring-authorization-server (9000)
```

## 快速开始

### 前置依赖

1. 启动 `spring-authorization-server` (9000)
2. MySQL + Redis 已就绪

### 启动

```bash
cd portal-server
mvn spring-boot:run
```

或指定环境：

```bash
mvn spring-boot:run -Dspring.profiles.active=dev   # 开发环境（默认）
mvn spring-boot:run -Dspring.profiles.active=prod  # 生产环境
```

## 客户端配置

| 参数 | 值 |
|------|------|
| client_id | `portal-app` |
| client_secret | `123456` |
| 认证方式 | `client_secret_basic` (Confidential Client) |
| 授权类型 | `authorization_code`, `refresh_token` |
| scopes | `openid, profile, email` |
| requireProofKey | `true`（强制 PKCE，现代安全实践） |
| redirect_uri | `http://localhost:8080/login/oauth2/code/portal-app-oidc` |
| post_logout_redirect_uri | `http://localhost:8000/logged-out` |

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/user/me` | 获取当前登录用户信息（从 OidcUser 提取） |
| GET | `/api/clients` | 获取可用客户端列表（代理调用认证中心 `/api/public/clients`） |
| GET | `/api/auth/callback-success` | OAuth2 登录成功后的默认跳转页 |
| GET | `/api/auth/logout` | 触发 OIDC RP-Initiated Logout |

## 关键设计

### 1. PKCE 自定义实现

虽然 portal-app 是 Confidential Client（有 client_secret），但客户端注册时已设置 `requireProofKey=true`。通过自定义 Bean 实现 PKCE：

- `pkceAuthorizationRequestResolver`：生成 32 字节 `code_verifier`，计算 `code_challenge = base64url(sha256(verifier))`，存入 OAuth2AuthorizationRequest 的 additionalParameters
- `pkceTokenResponseClient`：从 additionalParameters 取出 `code_verifier`，拼到 token 请求表单

### 2. 自定义 LogoutSuccessHandler

**为什么不用 `OidcClientInitiatedLogoutSuccessHandler`**：Spring Security 6.4 的该 Handler 通过 `providerDetails.getConfigurationMetadata().get("end_session_endpoint")` 获取端点，application.yml 中的 `logout-uri` 不会被映射到该 metadata key。当 `end_session_endpoint` 为 null 时，Handler 回退到默认行为（跳到 `/`），触发 OAuth2 重新登录循环。

**本模块的实现**：
1. 从 OidcUser 提取 `id_token` (JWT 原文)
2. 构建认证中心 `/logout` URL，携带 `id_token_hint` 和 `post_logout_redirect_uri`
3. 302 重定向到认证中心，由 OidcLogoutEndpointFilter 清除 SSO 会话
4. 认证中心验证 `post_logout_redirect_uri` 后，302 重定向回前端 `/logged-out` 页面

### 3. Cookie 隔离

```yaml
server.servlet.session.cookie.name: PORTAL_SERVER_SESSION
```

本应用与认证中心 (9000) 同在 localhost，默认 JSESSIONID cookie 会互相覆盖。设置独立 cookie 名避免 8080 → 9000 → 8080 跳转中丢失 HttpSession（HttpSession 中存有 OAuth2AuthorizationRequest，丢失会导致 state mismatch）。

### 4. CORS 配置

允许 `http://localhost:8000`（portal-app 前端）跨域调用，允许携带 Cookie (credentials)。

### 5. OAuth2 端点显式配置

为避免启动时通过 `issuer-uri` 自动发现失败（认证中心未启动时报错），显式配置所有端点：

```yaml
spring.security.oauth2.client.provider.spring-auth-server:
  authorization-uri: http://localhost:9000/oauth2/authorize
  token-uri: http://localhost:9000/oauth2/token
  jwk-set-uri: http://localhost:9000/oauth2/jwks
  user-info-uri: http://localhost:9000/userinfo
  logout-uri: http://localhost:9000/logout
  issuer-uri: http://localhost:9000
```

## 代码结构

```
net.xzh.portal
├── PortalApplication.java                  # 启动类
├── client/
│   └── AuthServerClient.java              # 调用认证中心公开 API
├── config/
│   └── SecurityConfig.java                # OAuth2 Client + PKCE + Logout 配置
├── controller/
│   ├── PageController.java                # 页面路由
│   └── PortalApiController.java           # REST API (/api/user/me, /api/clients)
└── security/
    └── TokenValidationFilter.java         # Token 校验过滤器
```

## 环境配置

通过 `spring.profiles.active` 切换 `application-{profile}.yml`：

- `dev`：开发环境（默认，认证中心 `http://localhost:9000`）
- `local`：本地调试
- `prod`：生产环境

## 相关文档

- [portal-app README](../portal-app/README.md)
- [统一认证管理平台设计说明书](../统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO 设计）
