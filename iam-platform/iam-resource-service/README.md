# Resource Service — 资源服务

独立 OAuth2 资源服务器，负责校验第三方传过来的 Bearer Token（Opaque）并承载受保护的业务 API。

- 端口：`9010`
- 依赖：Spring Boot 3.x + Spring Security OAuth2 Resource Server + MyBatis-Plus/Druid/MySQL
- 角色：**资源服务器**（持 `resource-server` 客户端凭证，调用认证中心 `/oauth2/introspect`）

## 架构定位

```
[各客户端/OAuth2 流程] ──► 授权码/密码/设备码/客户端模式获取 token
                                │
                                ▼
                        iam-authorization-server (9000)
                                ▲                  (Opaque token 校验)
                                │ /oauth2/introspect   │
                                │                      ▼
iam-resource-service (9010, 本模块)
                                 │
                                 ├─ /api/admin/**       管理端能力 (角色/权限, ROLE_ADMIN)
                                 ├─ /api/public/clients portal 端能力 (门户目录, permitAll)
                                 ├─ /api/contacts       公开端能力 (通讯录示例)
                                 └─ /api/internal/**    服务间内部能力 (供认证中心 M2M, ROLE_SERVICE)
```

认证中心原 Order(2) 资源服务器链（`/api/**` Bearer 认证）已随业务接口迁移到本模块，认证中心不再提供受保护的业务 API。

## 快速开始

### 前置依赖

1. 启动 `iam-authorization-server` (9000)
2. 其 `iam_identity.sql` 已通过 `mysql` 命令行初始化（含客户端 `resource-server`）
3. MySQL 已就绪；资源服务器**不依赖 Redis**，身份/权限直接查 MySQL

### 启动

```bash
cd iam-resource-service
mvn spring-boot:run
```

## 客户端配置

| 参数 | 值 |
|------|------|
| client_id | `resource-server` |
| client_secret | `123456` |
| introspection-uri | `http://localhost:9000/oauth2/introspect` |
| 认证方式 | `client_secret_basic` |

> 说明：`resource-server` 客户端 (id=`6`) 已在 `iam-authorization-server/src/main/resources/iam_identity.sql` 登记。
> 认证中心的 `EnrichedOAuth2TokenIntrospectionAuthenticationProvider` 会让所有授权流程（含授权码）
> 的 Opaque token 在内省时返回 `sub`（用户名），资源服务据此查询用户权限。

## API 一览

接口按能力域分四类，安全规则见 `ResourceServerConfig`，控制器分包对应：

| 能力域 | 控制器包 | 鉴权 |
|--------|---------|------|
| 管理端 | `controller/admin` | `ROLE_ADMIN` |
| portal 端 | `controller/portal` | `permitAll`（当前） |
| 公开端 | `controller/client` | 任意已认证 |
| 服务间内部（不属对外分类） | `controller/internal` | `ROLE_SERVICE`（M2M） |

### 管理端（`/api/admin/**`，Bearer + `ROLE_ADMIN`）

| 接口 | 说明 |
|------|------|
| `GET/POST /api/admin/roles`、`PUT/DELETE /api/admin/roles/{id}` | 角色 CRUD（修改可重绑权限 `permissionIds`） |
| `GET/POST /api/admin/permissions`、`PUT/DELETE /api/admin/permissions/{id}` | 权限 CRUD |

> 用户 ↔ 角色分配（`assignRolesToUser` / `listRoleIdsOfUser`）已实现于服务层但未暴露 REST；管理台规划 `/api/admin/users/{id}/roles`（`ROLE_ADMIN`），不并入内部接口。

### portal 端（`/api/public/clients`，门户客户端目录）

| 接口 | 说明 |
|------|------|
| `GET /api/public/clients` | 门户 SSO 跳转卡片所需的客户端列表（经 resource-server client_credentials 调认证中心 `/api/directory/clients`，60s 本地缓存） |

> 当前 `permitAll`（portal 端与公开端均可用）；若收紧为 portal 专属，改为校验 `client_id == portal-app`。

### 公开端（`/api/contacts`，任意已认证用户）

| 接口 | 说明 |
|------|------|
| `GET /api/contacts` | 通讯录示例（硬编码），并返回 sub 对应的 DB 身份/角色/权限 |
| `GET /api/contacts/{id}` | 通讯录详情 |

### 服务间内部（`/api/internal/**`，M2M，不属对外分类）

| 接口 | 说明 |
|------|------|
| `GET /api/internal/user/{username}/roles` | 按人返回 `{username, roles, permissions}`，只含编码不含凭据（供认证中心注入 id_token claims，**待接线，当前无调用方**） |

> 鉴权：`ROLE_SERVICE` + client_id 白名单双保险。服务令牌判定依据 `grant_type=client_credentials` 或 client_id ∈ `authserver.service-client-ids`（默认 `[resource-server]`），不依赖"本地查不到用户"反推——新用户（仅存 iam_identity 未同步）不会被误判为服务令牌。未来对外 API 服务平台接入时在 `service-client-ids` 追加其 client_id 即可。

> 身份与权限对应：`sub`（用户名）→ `sys_user` 查身份，经 `sys_user_role`→`sys_role`、
> `sys_role_permission`→`sys_permission` 解析角色与权限（如 `admin`=全部 5 个应用，
> `user`=portal+oa）。数据源为 `iam_authorization` 库，配置见 `application-dev.yml`。

> 能力分类与调用关系详见《统一认证管理平台设计说明书》§22.2 与 §23（谁能调用哪些能力）。

> 原 `/api/my-apps` 迁移方案：应用级权限目录改由门户侧按 `permissions` 过滤呈现，故不再提供 `my-apps` 接口（客户端目录由 `/api/public/clients` 承接）。

## 测试

见 [iam-authorization-server/test.http](../iam-authorization-server/test.http) 第 4 节资源服务用例。