# Spring Authorization Server — 统一认证中心

基于 Spring Authorization Server 1.4.1 的单体认证中心，提供 OAuth2 / OIDC 能力。管理后台页面使用 Thymeleaf 模板渲染（templates/admin/），不可直接通过 URL 访问静态资源。

- 端口：`9000`
- 依赖：MySQL 8（客户端 / 用户 / 授权同意 / 授权日志）、Redis（token / code / session 运行时状态）
- access_token 格式：**Opaque (REFERENCE)**，撤销即删 Redis key，无 JWT 黑名单
- id_token 格式：**JWT (RS256)**，仅 `openid` scope 且非 `client_credentials` 时签发

## 管理后台

管理后台位于 `/admin/**`，使用独立的 `AdminUserDetailsService`（ROLE_ADMIN）和独立的 SecurityContext，与门户完全隔离。页面由 Controller 渲染 Thymeleaf 模板，不可直接通过 URL 访问静态文件：

| 路径 | 页面 | 数据维护能力 |
|------|------|-------------|
| `/admin/login.html` | 管理员登录 | — |
| `/admin` | 开发手册首页 | 内置对接说明（客户端类型、OIDC、退出、架构） |
| `/admin/user` | 用户管理 | 用户 CRUD、启用/禁用、重置密码 |
| `/admin/client` | 客户端管理 | 客户端 CRUD、重置密钥 |
| `/admin/authorization` | 授权记录 | 查询授权同意（主表）+ 授权历史（子表）、撤销 |
| `/admin/online` | 在线管理 | 管理员列表 + 客户端用户（含门户），强制下线 |
| `/admin/monitor` | 运行监控 | 服务状态监控 |

> 门户已拆分为独立项目：iam-portal-web（8000 前端）+ iam-portal-service（8080 BFF），通过 OAuth2 授权码流程接入认证中心。

## 在线用户与会话管理

### 层级模型

```
User (用户)
  └─ SSO Session (一次认证产生的统一登录会话)
       └─ Client Session (该 SSO Session 使用过的客户端)
            ├─ Portal
            ├─ Web-App
            └─ Mobile-App
```

### 管理 API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/admin/online/users` | 统一在线用户列表（合并 SSO + 客户端会话） |
| GET | `/admin/users/{id}/sessions` | 用户会话层级视图 |
| POST | `/admin/users/{id}/logout` | 按用户踢下线（所有设备退出） |
| POST | `/admin/sessions/{id}/logout` | 按 SSO 会话踢下线（仅指定设备退出） |

### UI 设计要点

- 采用上下结构布局，上方为管理员列表（蓝色徽章），下方为客户端列表（绿色徽章）
- 管理员列表和客户端列表并行加载，独立的空状态提示
- SSO 会话卡片按钮文案为「终止会话」
- 客户端会话行按钮文案为「撤销令牌」
- 客户端会话详情：登录时间列后🔑按钮悬浮显示 Access Token，TOKEN 过期列后🔄按钮悬浮显示 Refresh Token
- SSO 会话登录时间 = `creationTime`，最近访问时间 = `lastAccessTime`
- 客户端会话登录时间 = `accessToken.issuedAt`，TOKEN 过期 = `accessToken.expiresAt`

## 开发说明 — 代码架构

```
net.xzh.authserver
├── AuthorizationServerApplication.java     # 启动类
├── common/                                  # 通用工具
│   └── Result.java                          #   统一响应封装
├── config/                                  # 基础设施配置
│   ├── JacksonConfig.java                   #   Jackson 序列化
│   ├── MybatisPlusConfig.java               #   MyBatis-Plus
│   └── RedisConfig.java                     #   Redis
├── controller/                              # Controller 层（按职责分包）
│   ├── admin/                               #   管理后台 API (/admin/**, /health)
│   │   ├── AdminPageController.java         #     管理后台页面路由
│   │   ├── UserController.java              #     用户管理 + 在线会话
│   │   ├── ClientController.java            #     客户端管理
│   │   ├── AuthorizationRecordController.java  #  授权记录
│   │   ├── OnlineSessionController.java     #     在线会话管理 API
│   │   └── HealthController.java            #     健康检查
│   ├── api/                                 #   业务 API (/api/**, Bearer 保护)
│   │   ├── ContactsController.java          #     通讯录（资源服务器示例）
│   │   └── PublicClientController.java       #     公开客户端列表 (/api/public/clients)
│   └── auth/                                #   认证类页面/端点
│       ├── LoginController.java             #     路由 (/, /admin, /portal)
│       ├── ConsentController.java           #     授权同意页 (/consent)
│       ├── DeviceActivateController.java    #     设备验证页 (/activate)
│       ├── LogoutController.java            #     OIDC Logout (支持 post_logout_redirect_uri / redirect)
│       └── UserInfoController.java          #     OIDC UserInfo (/userinfo)
├── entity/                                  # 实体（MyBatis-Plus）
│   ├── SysUser.java
│   ├── OAuth2RegisteredClient.java
│   ├── OAuth2AuthorizationConsentEntity.java
│   └── OAuth2AuthorizationRecordEntity.java
├── mapper/                                  # Mapper（MyBatis-Plus）
│   ├── SysUserMapper.java
│   ├── OAuth2RegisteredClientMapper.java
│   ├── OAuth2AuthorizationConsentMapper.java
│   └── OAuth2AuthorizationRecordMapper.java
├── service/                                 # 业务服务
│   ├── UserService.java                     #   用户 + 会话管理（含 kickOfflineSafely）
│   ├── ClientService.java                   #   客户端管理
│   └── AuthSessionService.java              #   授权会话 / 撤销（含 revokeBySsoSessionId）
├── vo/                                      # 视图对象
│   ├── ClientVO.java
│   ├── ClientSessionVO.java                 #   含 accessToken / refreshToken 字段
│   ├── OnlineUserVO.java
│   ├── SessionVO.java
│   └── SsoSessionVO.java
└── security/                                # 安全组件（核心）
    ├── AuthorizationServerConfig.java       #   总配置：4 条 FilterChain + TokenGenerator
    ├── authentication/                      #   【认证层】纯逻辑，不碰 HTTP
    │   ├── client/                          #     客户端认证逻辑
    │   │   └── DeviceClientAuthenticationProvider.java  # NONE 公共客户端认证（设备码/刷新令牌）
    │   └── grant/                           #     自定义授权模式逻辑（扁平，按文件名区分类型）
    │       ├── PasswordGrantAuthenticationProvider.java  # 密码模式 Provider（支持 id_token）
    │       ├── PasswordGrantAuthenticationToken.java     # 密码模式 Token 载体
    │       └── DeviceCodeGrantAuthenticationProvider.java # 设备码模式 Provider（替换 SAS 原生，支持 id_token + 真实 authorities）
    ├── repository/                          #   OAuth2 持久化
    │   ├── JdbcRegisteredClientRepository.java       # 客户端配置 (MySQL + Redis 缓存，强制 REFERENCE)
    │   ├── JdbcOAuth2AuthorizationConsentService.java # 授权同意 (MySQL) + 审计日志
    │   └── RedisOAuth2AuthorizationService.java      # 授权运行时状态 (Redis TTL，含 SSO Session 关联)
    ├── session/                             #   Session 管理
    │   └── RedisSessionRegistry.java        #     SSO 会话跟踪（含 creationTime / lastAccessTime / expired）
    ├── token/                               #   Token 内省
    │   └── RedisOpaqueTokenIntrospector.java         # Opaque Bearer token 校验 (Redis 查询)
    ├── userdetails/                         #   双 UserDetailsService（按角色隔离）
    │   ├── AdminUserDetailsService.java     #     管理员 (ROLE_ADMIN, Order 3)
    │   └── PortalUserDetailsService.java    #     门户 / 设备用户 (Order 5/6, 为 id_token 加载真实 authorities)
    └── web/                                 #   【Web 层】HTTP 请求处理
        ├── converter/                       #     AuthenticationConverter（请求 → 未认证 Token）
        │   ├── DeviceClientAuthenticationConverter.java  # 解析 device_code / refresh_token 请求
        │   └── PasswordGrantAuthenticationConverter.java  # 解析 password grant 请求
        ├── CompositeSecurityContextRepository.java   # SecurityContext 组合读写 (DEVICE→PORTAL 回退)
        ├── ActiveClientTrackingFilter.java           # 跟踪活跃客户端 (解析 Bearer Token 存入 Session)
        └── SessionExpirationFilter.java              # 会话过期检测 + 自动续签
```

### 认证链（4 条 SecurityFilterChain）

| Order | 匹配路径 | 认证方式 | SecurityContext |
|-------|---------|---------|-----------------|
| 1 | `/oauth2/**` `/consent` `/.well-known/**` `/login` `/logout` | OAuth2 客户端 + 表单 + Opaque | Composite (DEVICE→PORTAL) |
| 2 | `/api/**` | Bearer Opaque introspect | — (STATELESS) |
| 3 | `/admin/**` | 表单 (AdminUserDetailsService) | ADMIN |
| 5 | `/activate` `/device-login` | 表单 (PortalUserDetailsService) | DEVICE (一次性) |

> Order(4) 预留。三条表单链通过不同 HttpSession attribute key 隔离 SecurityContext。
> 门户已拆分为独立项目 (iam-portal-web + iam-portal-service)，不再需要 Order(6) 兜底链。

### 关键设计约束

- access_token 全局 Opaque：`OAuth2AccessTokenGenerator` 优先于 `JwtGenerator`，DB 配置被强制覆盖为 REFERENCE
- 设备码客户端 Converter 须同时匹配 device_code 与 refresh_token，返回 `OAuth2ClientAuthenticationToken` 兼容 SAS
- Token 端点用 `DelegatingAuthenticationConverter` 组合 5 个 Converter，不可单替换
- `revokeSession(id)` 只撤 Redis token，不终止 HttpSession；终止会话用 `revokeUserAll`
- `LogoutController` 同时支持 OIDC 标准 `post_logout_redirect_uri` 和自定义 `redirect` 参数
- `/admin/logout` 调用 `partialLogout(ADMIN_CONTEXT_KEY)` 仅清除管理员认证
- `/logout` 调用 `partialLogout(DEVICE_CONTEXT_KEY)` 清除设备认证，保留管理员
- partialLogout 在 `anyLeft=true` 时仍需调用 `removeSessionInformation()`，否则退出用户仍显示在在线列表
- 用户禁用 / 重置密码 / 修改用户信息 / 删除用户均触发 `kickOfflineSafely → revokeUserAll`

## 接入说明

### 选择客户端类型

| 接入方 | client_id | 模式 | 参考演示 |
|--------|-----------|------|---------|
| 门户（前后端分离） | `portal-app` | 授权码 + PKCE | [iam-portal-web](../iam-portal-web/README.md) + [iam-portal-service](../iam-portal-service/README.md) |
| 传统 Web 应用（有后端） | `web-app` | 授权码 / 密码 | [iam-client-web-demo](../iam-client-web-demo/README.md) |
| 输入受限设备（TV/IoT/CLI） | `device-app` | 设备码 (RFC 8628) | [iam-client-device-demo](../iam-client-device-demo/README.md) |
| 原生 App / SPA（无后端） | `mobile-app` | 授权码 + PKCE | [iam-client-mobile-demo](../iam-client-mobile-demo/README.md) |
| 后端服务间调用 (M2M) | `service-app` | 客户端模式 | 见 [test.http](./test.http) |

### 通用接入步骤

1. **发现端点**：`GET /.well-known/openid-configuration` 获取所有 OAuth2/OIDC 端点地址
2. **授权**：引导用户到 `/oauth2/authorize?...`（授权码 / 设备码）或直接 `POST /oauth2/token`（密码 / 客户端模式）
3. **换 token**：`POST /oauth2/token`，按模式带不同参数（授权码带 `code`，密码带 `username/password`，PKCE 带 `code_verifier`，客户端模式带 `client_secret`）
4. **调 API**：`Authorization: Bearer <access_token>` 调 `/api/**`
5. **获取用户信息**：`GET /userinfo`（需 `openid` scope）
6. **续期 / 退出**：`refresh_token` 续期（Public Client 不可用，用 `prompt=none` 静默重新授权），`/oauth2/revoke` 吊销 token，`/logout?post_logout_redirect_uri=` 销毁会话

### OIDC ID Token 签发条件

同时满足以下三个条件才会签发 ID Token：

1. 客户端注册时包含 `openid` scope
2. 授权类型不是 `client_credentials`
3. Token 请求中包含 `openid` scope

### 接口测试

完整的 curl / REST Client 测试用例见 [test.http](./test.http)，覆盖健康检查、4 种授权模式、资源访问、内省、撤销。可直接在 VS Code / IntelliJ 中逐条执行。

## 数据库

建表脚本 [schema.sql](./src/main/resources/schema.sql)，含 4 张表：

| 表 | 用途 | 存储 |
|----|------|------|
| `sys_user` | 系统用户 | MySQL |
| `oauth2_registered_client` | 客户端配置 | MySQL |
| `oauth2_authorization_consent` | 授权同意 | MySQL |
| `oauth2_authorization_record` | 授权历史日志 | MySQL |
| _(运行时 token/code)_ | access_token / refresh_token / code / device_code | Redis (TTL 自动过期) |

> 不建 `oauth2_authorization` 表，运行时状态全部在 Redis，撤销即删 key。

## 默认账号

| 账号 | 密码 | 角色 | 用途 |
|------|------|------|------|
| `admin` | `123456` | ROLE_ADMIN | 管理后台 |
| `user` | `123456` | ROLE_USER | 演示项目登录 |

## 默认客户端

| client_id | 模式 | 认证方式 | 适用场景 |
|-----------|------|---------|---------|
| `portal-app` | 授权码 + PKCE | client_secret_basic | 门户 BFF |
| `web-app` | 授权码 / 密码 | client_secret_basic | 传统 Web 应用 |
| `device-app` | 设备码 | none | 电视 / IoT / CLI |
| `mobile-app` | 授权码 + PKCE | none | 原生 App / SPA |
| `service-app` | 客户端模式 | client_secret_basic | 服务间调用 (M2M) |

客户端配置详见 [schema.sql](./src/main/resources/schema.sql)，对接方式见各演示项目 README。

## 相关文档

- [统一认证管理平台设计说明书](../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO、在线用户与会话管理、测试方案）
