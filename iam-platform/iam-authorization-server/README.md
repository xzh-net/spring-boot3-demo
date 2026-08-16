# Spring Authorization Server — 统一认证中心

基于 Spring Authorization Server 1.4.1 的单体认证中心，提供 OAuth2 / OIDC 能力。管理后台已剥离为独立工程（[iam-admin-service](../iam-admin-service) + [iam-admin-web](../iam-admin-web)，见下方「管理后台」）。

- 端口：`9000`
- 依赖：MySQL 8（客户端 / 用户 / 授权同意 / 授权日志，库 `iam_identity`）、Redis（token / code / session 运行时状态）
- access_token 格式：**Opaque (REFERENCE)**，撤销即删 Redis key，无 JWT 黑名单
- id_token 格式：**JWT (RS256)**，仅 `openid` scope 且非 `client_credentials` 时签发

## 管理后台

管理后台自 V6 起由独立模块提供，认证中心仅暴露管理 REST API：

| 模块 | 端口 | 说明 |
|------|------|------|
| `iam-admin-service` | 8085 | 管理 BFF：OAuth2 Client (`admin-app`) 授权码登录认证中心，Bearer 透传管理 API |
| `iam-admin-web` | 8001 | 纯 HTML 管理台（用户/客户端/授权/在线/监控），由 admin-service 代理后端 |

访问 `http://localhost:8001` → 任一管理页触发登录 → 跳转认证中心登录页（`admin / 123456`）→ 回跳管理台。
页面调用的 `GET /api/admin/**` 等管理 API 由认证中心 Order(2) 安全链保护（Bearer + `ADMIN_SERVICE_TOKEN`）。

> 认证中心的 `/admin/**` 页面、`AdminUserDetailsService`、`templates/admin/*` 已随迁移删除。

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

三域管理 REST API 经 `/api/admin/**` 暴露（Order(2) 安全链：Bearer + `ADMIN_SERVICE_TOKEN`），由管理后台 / 运维脚本调用：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET/POST/PUT/DELETE | `/api/admin/users` ... | 用户域 CRUD、启用/禁用、重置密码、踢会话 |
| GET/POST/PUT/DELETE | `/api/admin/clients` ... | 客户端域 CRUD、重置密钥 |
| GET | `/api/admin/sessions/online` | 统一在线用户列表（合并 SSO + 客户端会话） |
| GET | `/api/admin/sessions/users/{id}` | 用户会话层级视图 |
| POST | `/api/admin/sessions/users/{id}/logout` | 按用户踢下线（所有设备退出） |
| POST | `/api/admin/sessions/{ssoSessionId}/logout` | 按 SSO 会话踢下线（仅指定设备退出） |
| DELETE | `/api/admin/sessions/online/{username}` | 按用户撤销客户端令牌 |
| GET | `/api/admin/records/consents` | 授权同意主表 |
| GET/DELETE | `/api/admin/records` | 授权历史 / 取消授权 |

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
│   ├── api/                                 #   管理 REST API（三域）
│   │   ├── AdminUserApiController.java      #     /api/admin/users 用户域
│   │   ├── AdminClientApiController.java    #     /api/admin/clients 客户端域
│   │   ├── AdminSessionApiController.java   #     /api/admin/sessions 会话域
│   │   └── AdminRecordApiController.java    #     /api/admin/records 授权记录域
│   └── auth/                                #   认证类页面/端点
│       ├── LoginController.java             #     路由 (/, /portal)
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
    ├── AuthorizationServerConfig.java       #   总配置：3 条 FilterChain + TokenGenerator
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
    ├── userdetails/                         #   UserDetailsService
    │   └── PortalUserDetailsService.java    #     统一账号 (admin/普通用户, 为 id_token 加载真实 authorities)
    └── web/                                 #   【Web 层】HTTP 请求处理
        ├── converter/                       #     AuthenticationConverter（请求 → 未认证 Token）
        │   ├── DeviceClientAuthenticationConverter.java  # 解析 device_code / refresh_token 请求
        │   └── PasswordGrantAuthenticationConverter.java  # 解析 password grant 请求
        ├── CompositeSecurityContextRepository.java   # SecurityContext 组合读写 (DEVICE→PORTAL 回退)
        ├── ActiveClientTrackingFilter.java           # 跟踪活跃客户端 (解析 Bearer Token 存入 Session)
        └── SessionExpirationFilter.java              # 会话过期检测 + 自动续签
```

### 认证链（3 条 SecurityFilterChain）

| Order | 匹配路径 | 认证方式 | SecurityContext |
|-------|---------|---------|-----------------|
| 1 | `/oauth2/**` `/consent` `/.well-known/**` `/login` `/logout` `/userinfo` | OAuth2 客户端 + 表单 | Composite (DEVICE→PORTAL) |
| 2 | `/api/admin/**` | Bearer (RedisOpaqueTokenIntrospector) | — |
| 5 | `/activate` `/device-login` | 表单 (PortalUserDetailsService) | DEVICE (一次性) |

> 原 Order(2) 资源服务器链 (/api/** Bearer 认证) 已随业务接口迁移到独立项目
> [iam-resource-service](../iam-resource-service/README.md) (:9010)。
> 认证中心保留的管理 API 位于 Order(2) 链：`/api/admin/**`（Bearer + `ADMIN_SERVICE_TOKEN`）。
> 认证相关的 /userinfo 仍由本中心提供（Bearer 校验由 UserInfoController 自省实现）。
> Order(3) 原管理后台表单链已随管理台迁移删除；Order(4) 预留。
> 门户已拆分为独立项目 (iam-portal-web + iam-portal-service)，不再需要 Order(6) 兜底链。

### 关键设计约束

- access_token 全局 Opaque：`OAuth2AccessTokenGenerator` 优先于 `JwtGenerator`，DB 配置被强制覆盖为 REFERENCE
- 设备码客户端 Converter 须同时匹配 device_code 与 refresh_token，返回 `OAuth2ClientAuthenticationToken` 兼容 SAS
- Token 端点用 `DelegatingAuthenticationConverter` 组合 5 个 Converter，不可单替换
- `revokeSession(id)` 只撤 Redis token，不终止 HttpSession；终止会话用 `revokeUserAll`
- `LogoutController` 同时支持 OIDC 标准 `post_logout_redirect_uri` 和自定义 `redirect` 参数
- `/logout` 调用 `partialLogout(DEVICE_CONTEXT_KEY)` 清除设备认证
- partialLogout 在 `anyLeft=true` 时仍需调用 `removeSessionInformation()`，否则退出用户仍显示在在线列表
- 用户禁用 / 重置密码 / 修改用户信息 / 删除用户均触发 `kickOfflineSafely → revokeUserAll`

## 接入说明

### 选择客户端类型

| 接入方 | client_id | 模式 | 参考演示 |
|--------|-----------|------|---------|
| 门户（前后端分离） | `portal-app` | 授权码 + PKCE | [iam-portal-web](../iam-portal-web/README.md) + [iam-portal-service](../iam-portal-service/README.md) |
| 传统 Web 应用（有后端） | `web-app` | 授权码 / 密码 | [example/iam-client-web-demo](../example/iam-client-web-demo/README.md) |
| 输入受限设备（TV/IoT/CLI） | `device-app` | 设备码 (RFC 8628) | [example/iam-client-device-demo](../example/iam-client-device-demo/README.md) |
| 原生 App / SPA（无后端） | `mobile-app` | 授权码 + PKCE | [example/iam-client-mobile-demo](../example/iam-client-mobile-demo/README.md) |
| 后端服务间调用 (M2M) | `service-app` | 客户端模式 | 见 [test.http](./test.http) |

### 通用接入步骤

1. **发现端点**：`GET /.well-known/openid-configuration` 获取所有 OAuth2/OIDC 端点地址
2. **授权**：引导用户到 `/oauth2/authorize?...`（授权码 / 设备码）或直接 `POST /oauth2/token`（密码 / 客户端模式）
3. **换 token**：`POST /oauth2/token`，按模式带不同参数（授权码带 `code`，密码带 `username/password`，PKCE 带 `code_verifier`，客户端模式带 `client_secret`）
4. **调 API**：`Authorization: Bearer <access_token>` 调业务 API（见 [iam-resource-service](../iam-resource-service/README.md)，:9010，如 `/api/contacts`）
5. **获取用户信息**：`GET /userinfo`（需 `openid` scope）
6. **续期 / 退出**：`refresh_token` 续期（Public Client 不可用，用 `prompt=none` 静默重新授权），`/oauth2/revoke` 吊销 token，`/logout?post_logout_redirect_uri=` 销毁会话

### OIDC ID Token 签发条件

同时满足以下三个条件才会签发 ID Token：

1. 客户端注册时包含 `openid` scope
2. 授权类型不是 `client_credentials`
3. Token 请求中包含 `openid` scope

### 接口测试

完整的 curl / REST Client 测试用例见 [test.http](./test.http)，覆盖 4 种授权模式、资源访问、内省、撤销、管理 API、管理后台模块（admin-service / admin-web），可直接在 VS Code / IntelliJ 中逐条执行。

## 数据库

身份库建表脚本 [iam_identity.sql](./src/main/resources/iam_identity.sql)（库 `iam_identity`），含 4 张表：

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
| `admin` | `123456` | ADMIN（业务角色，令牌注入 `ADMIN_SERVICE_TOKEN`） | 管理后台 |
| `user` | `123456` | USER（业务角色，默认 `ROLE_USER`） | 演示项目登录 |

## 默认客户端

| client_id | 模式 | 认证方式 | 适用场景 |
|-----------|------|---------|---------|
| `portal-app` | 授权码 + PKCE | client_secret_basic | 门户 BFF |
| `admin-app` | 授权码 | client_secret_basic | 管理后台 BFF (8085) |
| `web-app` | 授权码 / 密码 | client_secret_basic | 传统 Web 应用 |
| `device-app` | 设备码 | none | 电视 / IoT / CLI |
| `mobile-app` | 授权码 + PKCE | none | 原生 App / SPA |
| `service-app` | 客户端模式 | client_secret_basic | 服务间调用 (M2M) |
| `resource-server` | 客户端模式 | client_secret_basic | 资源中心 introspection / 目录 API |

客户端配置详见 [iam_identity.sql](./src/main/resources/iam_identity.sql)（运行时由 `DataInitializer` 兜底创建），对接方式见各演示项目 README。

## 相关文档

- [统一认证管理平台设计说明书](../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO、在线用户与会话管理、测试方案）
