# 统一认证中心（单服务合并形态）

基于 Spring Authorization Server 1.4.1 的统一认证管理平台，提供 OAuth2 / OIDC 能力。**平台已合并为单服务单库**：原认证中心 (`iam-authorization-server`) 与原资源中心 (`iam-resource-service`) 合并为 **9000 单服务**（包结构 `net.xzh.iam.{common,auth,resource}`），单 MySQL 库 **`iam`**（17 表）。`iam-resource-service/` 仅作历史对照保留（见其 README 顶部归档说明）。

## 项目结构

| 项目 | 类型 | 端口 | 说明 | 文档 |
|------|------|------|------|------|
| `iam-authorization-server` | 服务端 (Java) | 9000 | **合并单服务**：OAuth2 端点 + 三域管理 API + RBAC/管理/业务 API（单库 `iam`） | [README](./iam-authorization-server/README.md) |
| `iam-resource-service` | （已归档） | — | 原资源中心，已并入 9000；仅作对照，不再启动 | [README](./iam-resource-service/README.md) |
| `bff/iam-admin-bff` | 管理后台服务 (Java) | 8085 | 管理 BFF：以 OAuth2 Client (admin-app) 授权码登录，Bearer 透传管理 API | |
| `web/iam-admin-web` | 管理后台前端 (Node) | 8001 | 纯 HTML 管理台：用户/客户端/授权/在线/监控，经 admin-bff 调后端 | |
| `web/iam-portal-web` | 门户前端 (Node) | 8000 | 纯前端，展示客户端列表与 SSO 跳转卡片 | |
| `bff/iam-portal-bff` | 门户 BFF (Java) | 8080 | OAuth2 Client (Confidential + PKCE)，持有 client_secret | |
| `client/iam-client-web-demo` | 演示 (Node) | 8081 | 授权码 / 密码模式 — 传统 Web 应用 (Confidential Client) | |
| `client/iam-client-device-demo` | 演示 (Node) | 8082 | 设备码模式 — 输入受限设备 (RFC 8628) | |
| `client/iam-client-mobile-demo` | 演示 (Node) | 8083 | 授权码 + PKCE — 移动应用 / SPA (Public Client) | |

## 快速启动

### 1. 初始化数据库（单库 `iam`）

依赖 MySQL 8 + Redis。导入合并基线脚本（单库 17 表，零租户）：

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam DEFAULT CHARSET utf8mb4"
mysql -u root -p iam < iam-authorization-server/src/main/resources/iam.sql
# 迁移脚本 iam-authorization-server/src/main/resources/migration/ (V6.1–V6.13) 供既有库升级
```

### 2. 启动合并单服务

修改 `iam-authorization-server/src/main/resources/application-{profile}.yml` 中的数据库 / Redis 连接后启动：

```bash
cd iam-authorization-server
mvn spring-boot:run    # http://localhost:9000
```

### 3. 启动管理后台

管理后台由独立的 BFF (8085) + 纯 HTML 前端 (8001) 组成，管理员经 OAuth2 授权码登录：

```bash
cd bff/iam-admin-bff && mvn spring-boot:run   # http://localhost:8085  管理后台 BFF
cd web/iam-admin-web && node server.js             # http://localhost:8001  管理后台前端
```

访问 http://localhost:8001 → 任一管理页触发登录 → 自动跳转登录页（账号 `admin / 123456`）→ 登录成功回跳管理台。

### 4. 启动门户（前后端分离）

```bash
cd bff/iam-portal-bff && mvn spring-boot:run  # http://localhost:8080  门户 BFF
cd web/iam-portal-web && node server.js            # http://localhost:8000  门户前端
```

### 5. 启动演示项目（按需）

```bash
cd client/iam-client-web-demo     && node server.js   # http://localhost:8081  传统 Web 应用
cd client/iam-client-device-demo  && node server.js   # http://localhost:8082  设备码
cd client/iam-client-mobile-demo  && node server.js   # http://localhost:8083  移动应用 / SPA
```

Node.js 演示项目均零依赖，仅需 Node.js。

一键启停全部核心服务：`powershell -ExecutionPolicy Bypass -File .\start-all.ps1`

## 启动顺序

1. **MySQL + Redis**（依赖，建库 `iam` 并导入 `iam.sql`）
2. **iam-authorization-server**（9000）：单服务承载协议端点与全部业务 API，其他服务通过 OIDC discovery 获取端点配置
3. **bff/iam-admin-bff**（8085）+ **web/iam-admin-web**（8001）：管理后台
4. **bff/iam-portal-bff**（8080）+ **web/iam-portal-web**（8000）：门户
5. 各业务系统 Demo（8081 / 8082 / 8083）：按需启动

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
| ~~`service-app`~~ | — | — | **已退役**（client_credentials 测试账号，无程序特判/消费方） |

客户端配置详见 [iam.sql](./iam-authorization-server/src/main/resources/iam.sql)，对接方式见各演示项目 README。

## 核心特性

- **单服务单库合并**：原认证中心与资源中心合并为 9000 单服务、单库 `iam`（17 表，零租户），角色加载/准入校验全部进程内完成，无服务间调用
- **三域管理 API**：`/api/admin/**`（用户/客户端/会话/授权记录四域，Bearer + `ADMIN_SERVICE_TOKEN`）
- **OAuth2 / OIDC 完整协议**：授权码、密码、客户端模式、设备码、刷新令牌
- **PKCE 支持**：Public Client 强制启用，Confidential Client (portal-app) 也启用
- **双向 SSO**：门户 ↔ 客户端互认登录态，`prompt=none` 静默授权
- **Opaque Token**：Access Token / Refresh Token 均为 Opaque，撤销即删 Redis key
- **JWT ID Token**：RS256 签名，携带用户 authorities
- **在线用户与会话管理**：按用户 / 按 SSO 会话强制下线，层级视图展示
- **管理后台**：独立 `iam-admin-bff` (8085) + `iam-admin-web` (8001)，纯 HTML 页面，管理员经认证中心授权码 SSO 登录后管理用户、客户端、授权记录、在线会话与运行监控
- **前后端分离门户**：iam-portal-web + iam-portal-bff BFF 架构
- **多环境配置**：dev / local / prod 通过 `spring.profiles.active` 切换

## 设计文档

- [统一认证管理平台设计说明书](./docs/统一认证管理平台设计说明书.md)（V4.0 完整版，整合 V3.1 基线 + OIDC/PKCE SSO + 在线用户与会话管理 + 测试方案）
