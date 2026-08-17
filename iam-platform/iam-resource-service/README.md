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
                                 ├─ /api/admin/**       管理端能力 (角色/权限, ADMIN_SERVICE_TOKEN)
                                 ├─ /api/public/clients/mine portal 端能力 (门户应用中心卡片, PORTAL_SERVICE_TOKEN + 门户客户端白名单)
                                 ├─ /api/capability/**  开放能力 (通讯录示例, 任意凭证 + 客户端订阅)
                                 └─ /api/internal/**    服务间内部能力 (供认证中心 M2M, PORTAL_SERVICE_TOKEN)
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
| 管理端 | `controller/admin` | `ADMIN_SERVICE_TOKEN`（管理服务凭证，管理员令牌或**管理 M2M 服务凭证** `admin-m2m`） |
| portal 端 | `controller/portal` | `PORTAL_SERVICE_TOKEN`（门户服务凭证，仅门户客户端签发令牌）+ 门户客户端白名单（`authserver.portal-client-ids`，默认 portal-app） |
| 其他 | `controller/permitall` | `PERMIT_ALL`（无认证，仅测试接口，不需要权限的示例归 other 域） |
| 开放能力 | `controller/capability` | 任意凭证 + 客户端能力订阅（`CAPABILITY`） |
| 服务间内部（**只读内省**，不属对外分类） | `controller/internal` | `PORTAL_SERVICE_TOKEN`（门户服务凭证）+ client_id 服务白名单双保险 |

> 分包 ↔ 能力域 ↔ 默认准入推导 / 凭证矩阵 / 用户生命周期事件边界，统一见 [`docs/开发规范.md`](../docs/开发规范.md) §4、§5。

### 管理端（`/api/admin/**`，Bearer + `ADMIN_SERVICE_TOKEN`）

| 接口 | 说明 |
|------|------|
| `GET/POST /api/admin/roles`、`PUT/DELETE /api/admin/roles/{id}` | 角色 CRUD（修改可重绑权限 `permissionIds`） |
| `GET/POST /api/admin/permissions`、`PUT/DELETE /api/admin/permissions/{id}` | 权限 CRUD |
| `DELETE /api/admin/users/{userCode}/data` | 删除用户联动清理（角色绑定 + USER 主体应用授权），幂等；以**管理 M2M 服务凭证**（认证中心 `admin-m2m`）或管理员令牌调用，V6.9 自 `/api/internal/user/{userCode}/data` 迁入管理端能力 |

> 用户 ↔ 角色分配（`assignRolesToUser` / `listRoleIdsOfUser`）已实现于服务层但未暴露 REST；管理台规划 `/api/admin/users/{id}/roles`（`ADMIN_SERVICE_TOKEN`），不并入内部接口。

### portal 端（`/api/public/clients/mine`，门户应用中心卡片）

| 接口 | 说明 |
|------|------|
| `GET /api/public/clients/mine` | 当前人员可见客户端列表（携带用户 Bearer，按应用授权过滤） |

> 准入：`PORTAL_SERVICE_TOKEN`（门户服务凭证，仅门户应用客户端 `portal-app` 签发的令牌由内省器注入）+ 门户客户端白名单（`authserver.portal-client-ids`，默认 `[portal-app]`）双闸门；
> 门户信息仅对门户客户端开放，非门户客户端（含匿名）一律 403/401。

### 开放能力（`/api/capability/**`，任意凭证 + 客户端订阅，V6.5 起由 `/api/contacts` 迁入）

| 接口 | 能力 | 说明 |
|------|------|------|
| `GET /api/capability/contacts` | contact:query | 通讯录示例（硬编码），并返回 sub 对应的 DB 身份/角色/权限 |
| `GET /api/capability/contacts/{id}` | contact:detail | 通讯录详情 |

### 其他（`/api/permitall/**`，无认证，不需要权限的接口示例，归 other 域）

| 接口 | 说明 |
|------|------|
| `GET /api/permitall/time` | 返回服务端当前时间（连通性 / 系统时间自测，不需要权限的接口示例，接口准入归 other 域 + PERMIT_ALL） |

### 服务间内部（`/api/internal/**`，M2M，不属对外分类，**仅只读内省**）

| 接口 | 说明 |
|------|------|
| `GET /api/internal/user/{username}/roles` | 按人返回 `{username, roles, permissions}`，只含编码不含凭据（认证中心 `PortalUserDetailsService→RemoteRoleService` 已接线，注入 id_token claims） |

> 本域对标认证中心内省接口（/oauth2/introspect），**只承载只读**；管理写（如删除用户联动清理）归管理端能力 `controller/admin` + 管理 M2M 服务凭证（见上「管理端」与 [`docs/开发规范.md`](../docs/开发规范.md) §4.3）。

> 鉴权为**硬规则**：`PORTAL_SERVICE_TOKEN` 且 client_id=`resource-server`（认证中心 M2M），由 `EndpointAdmissionManager` 按 `/api/internal/**` 前缀前置裁决；**不进入 `iam_endpoint_policy` 规则表、不经 `authserver.service-client-ids` 配置、管理端不可改**（V6.10 起，internal 域由 `EndpointPolicyScanInitializer` 整域跳过/清理）。

> 身份与权限对应：`sub`（用户名）→ `sys_user` 查身份，经 `sys_user_role`→`sys_role`、
> `sys_role_permission`→`sys_permission` 解析角色与权限（如 `admin`=全部 5 个应用，
> `user`=portal+oa）。数据源为 `iam_authorization` 库，配置见 `application-dev.yml`。

> 能力分类与调用关系详见《统一认证管理平台设计说明书》§22.2 与 §23（谁能调用哪些能力）。

> 原 `/api/my-apps` 迁移方案：应用级权限目录改由门户侧按 `permissions` 过滤呈现，故不再提供 `my-apps` 接口（客户端目录由 `/api/public/clients/mine` 承接）。

## 测试

见 [iam-authorization-server/test.http](../iam-authorization-server/test.http) 第 4 节资源服务用例。