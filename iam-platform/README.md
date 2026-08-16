# 统一认证中心

基于 Spring Authorization Server 1.4.1 的统一认证管理平台，提供 OAuth2 / OIDC 能力，配套门户（前后端分离）和 3 个对接演示项目，覆盖主流接入场景。

## 项目结构

| 项目 | 类型 | 端口 | 说明 | 文档 |
|------|------|------|------|------|
| `iam-authorization-server` | 服务端 (Java) | 9000 | 认证中心（身份库 iam_identity）：OAuth2 端点、三域管理 API、客户端目录 API | [README](./iam-authorization-server/README.md) |
| `iam-resource-service` | 资源中心 (Java) | 9010 | 资源中心（授权库 iam_authorization）：RBAC + 管理 API + 业务 API | |
| `iam-admin-service` | 管理后台服务 (Java) | 8085 | 管理 BFF：以 OAuth2 Client (admin-app) 授权码登录认证中心，Bearer 透传管理 API | |
| `iam-admin-web` | 管理后台前端 (Node) | 8001 | 纯 HTML 管理台：用户/客户端/授权/在线/监控，经 admin-service 调后端 | |
| `iam-portal-web` | 门户前端 (Node) | 8000 | 纯前端，展示客户端列表与 SSO 跳转卡片 | [README](./iam-portal-web/README.md) |
| `iam-portal-service` | 门户 BFF (Java) | 8080 | OAuth2 Client (Confidential + PKCE)，持有 client_secret | [README](./iam-portal-service/README.md) |
| `example/iam-client-web-demo` | 演示 (Node) | 8081 | 授权码 / 密码模式 — 传统 Web 应用 (Confidential Client) | [README](./example/iam-client-web-demo/README.md) |
| `example/iam-client-device-demo` | 演示 (Node) | 8082 | 设备码模式 — 输入受限设备 (RFC 8628) | [README](./example/iam-client-device-demo/README.md) |
| `example/iam-client-mobile-demo` | 演示 (Node) | 8083 | 授权码 + PKCE — 移动应用 / SPA (Public Client) | [README](./example/iam-client-mobile-demo/README.md) |

## 快速启动

### 1. 初始化数据库（V6 分库）

依赖 MySQL 8 + Redis。导入两份建表脚本（分别建立两个库）：

```bash
# 认证中心身份库 (iam_identity): 用户、OAuth2 客户端、授权记录
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam_identity DEFAULT CHARSET utf8mb4"
mysql -u root -p iam_identity < iam-authorization-server/src/main/resources/iam_identity.sql

# 资源中心授权库 (iam_authorization): RBAC 四表 + 业务数据
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam_authorization DEFAULT CHARSET utf8mb4"
mysql -u root -p iam_authorization < iam-resource-service/src/main/resources/iam_authorization.sql
```

### 2. 启动认证中心

修改 `iam-authorization-server/src/main/resources/application-{profile}.yml` 中的数据库 / Redis 连接后启动：

```bash
cd iam-authorization-server
mvn spring-boot:run
```

### 3. 启动资源中心

```bash
cd iam-resource-service && mvn spring-boot:run   # http://localhost:9010
```

### 4. 启动管理后台（管理台已从认证中心剥离）

管理后台由独立的 BFF (8085) + 纯 HTML 前端 (8001) 组成，管理员经认证中心 OAuth2 授权码登录：

```bash
cd iam-admin-service && mvn spring-boot:run   # http://localhost:8085  管理后台 BFF
cd iam-admin-web && node server.js        # http://localhost:8001  管理后台前端
```

访问 http://localhost:8001 → 任一管理页触发登录 → 自动跳转认证中心登录页（账号 `admin / 123456`）→ 登录成功回跳管理台。

### 5. 启动门户（前后端分离）

```bash
cd iam-portal-service && mvn spring-boot:run   # http://localhost:8080  门户 BFF
cd iam-portal-web && node server.js       # http://localhost:8000  门户前端
```

### 6. 启动演示项目（按需）

```bash
cd example/iam-client-web-demo     && node server.js   # http://localhost:8081  传统 Web 应用
cd example/iam-client-device-demo  && node server.js   # http://localhost:8082  设备码
cd example/iam-client-mobile-demo  && node server.js   # http://localhost:8083  移动应用 / SPA
```

Node.js 演示项目均零依赖，仅需 Node.js；Java 演示项目需要 Maven。

## 启动顺序

1. **MySQL + Redis**（依赖，建两库并导入脚本）
2. **iam-authorization-server**（9000）：其他服务通过 OIDC discovery 获取端点配置
3. **iam-resource-service**（9010）：依赖认证中心 Token / Introspect / 客户端目录 API
4. **iam-admin-service**（8085）+ **iam-admin-web**（8001）：管理后台，依赖认证中心登录与 API
5. **iam-portal-service**（8080）+ **iam-portal-web**（8000）：门户
6. 各业务系统 Demo（8081 / 8082 / 8083）：按需启动

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

客户端配置详见 [iam_identity.sql](./iam-authorization-server/src/main/resources/iam_identity.sql)，对接方式见各演示项目 README。

## 核心特性

- **V6 数据分库**：认证中心身份库 `iam_identity`（用户/客户端/授权记录）与 资源中心授权库 `iam_authorization`（RBAC/业务）分离；客户端目录经认证中心 `GET /api/directory/clients` 下发，资源中心不再直读客户端表
- **三域管理 API**：认证中心 `/api/admin/**`（用户/客户端/会话/授权记录四域，Bearer + `ADMIN_SERVICE_TOKEN`）
- **OAuth2 / OIDC 完整协议**：授权码、密码、客户端模式、设备码、刷新令牌
- **PKCE 支持**：Public Client 强制启用，Confidential Client (portal-app) 也启用
- **双向 SSO**：门户 ↔ 客户端互认登录态，`prompt=none` 静默授权
- **Opaque Token**：Access Token / Refresh Token 均为 Opaque，撤销即删 Redis key
- **JWT ID Token**：RS256 签名，携带用户 authorities
- **在线用户与会话管理**：按用户 / 按 SSO 会话强制下线，层级视图展示
- **管理后台**：独立 `iam-admin-service` (8085) + `iam-admin-web` (8001)，纯 HTML 页面，管理员经认证中心授权码 SSO 登录后管理用户、客户端、授权记录、在线会话与运行监控
- **前后端分离门户**：iam-portal-web + iam-portal-service BFF 架构
- **多环境配置**：dev / local / prod 通过 `spring.profiles.active` 切换

## 设计文档

- [统一认证管理平台设计说明书](./docs/统一认证管理平台设计说明书.md)（V4.0 完整版，整合 V3.1 基线 + OIDC/PKCE SSO + 在线用户与会话管理 + 测试方案）
