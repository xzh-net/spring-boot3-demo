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
                                 ├─ /api/contacts       通讯录示例 (硬编码)
                                 └─ /api/public/clients 公开客户端列表 (查 DB)
```

认证中心原 Order(2) 资源服务器链（`/api/**` Bearer 认证）已随业务接口迁移到本模块，认证中心不再提供受保护的业务 API。

## 快速开始

### 前置依赖

1. 启动 `iam-authorization-server` (9000)
2. 其 `schema.sql` 已通过 `mysql` 命令行初始化（含客户端 `resource-server`）
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

> 说明：`resource-server` 客户端 (id=`6`) 已在 `iam-authorization-server/src/main/resources/schema.sql` 登记。
> 认证中心的 `EnrichedOAuth2TokenIntrospectionAuthenticationProvider` 会让所有授权流程（含授权码）
> 的 Opaque token 在内省时返回 `sub`（用户名），资源服务据此查询用户权限。

## API 一览

| 接口 | 说明 | 权限 |
|------|------|------|
| `GET /api/contacts` | 通讯录示例（硬编码），并返回 sub 对应的 DB 身份/角色/权限 | 任意登录用户 |
| `GET /api/contacts/{id}` | 通讯录详情 | 任意登录用户 |
| `GET /api/public/clients` | 公开客户端列表（查询 `oauth2_registered_client`） | 公开（无需认证） |

> 身份与权限对应：`sub`（用户名）→ `sys_user` 查身份，经 `sys_user_role`→`sys_role`、
> `sys_role_permission`→`sys_permission` 解析角色与权限（如 `admin`=全部 5 个应用，
> `user`=portal+oa）。数据源与认证中心同库（`oauth2_server`），配置见 `application-dev.yml`。

> 原 `/api/my-apps` 迁移方案：资源服务器仅保留两个 API（通讯录 + 客户端列表），
> 应用级权限目录改由门户侧按 `permissions` 过滤呈现，故不再提供 `my-apps` 接口。

## 测试

见 [iam-authorization-server/test.http](../iam-authorization-server/test.http) 第 4 节资源服务用例。