# 统一认证中心

基于 Spring Authorization Server 1.4.1 的统一认证管理平台，提供 OAuth2 / OIDC 能力，配套门户（前后端分离）和 3 个对接演示项目，覆盖主流接入场景。

## 项目结构

| 项目 | 类型 | 端口 | 说明 | 文档 |
|------|------|------|------|------|
| `iam-authorization-server` | 服务端 (Java) | 9000 | 认证中心主体，含管理后台、OAuth2 端点、资源 API | [README](./iam-authorization-server/README.md) |
| `iam-portal-web` | 门户前端 (Node) | 8000 | 纯前端，展示客户端列表与 SSO 跳转卡片 | [README](./iam-portal-web/README.md) |
| `iam-portal-service` | 门户 BFF (Java) | 8080 | OAuth2 Client (Confidential + PKCE)，持有 client_secret | [README](./iam-portal-service/README.md) |
| `iam-client-web-demo` | 演示 (Node) | 8081 | 授权码 / 密码模式 — 传统 Web 应用 (Confidential Client) | [README](./iam-client-web-demo/README.md) |
| `iam-client-device-demo` | 演示 (Node) | 8082 | 设备码模式 — 输入受限设备 (RFC 8628) | [README](./iam-client-device-demo/README.md) |
| `iam-client-mobile-demo` | 演示 (Node) | 8083 | 授权码 + PKCE — 移动应用 / SPA (Public Client) | [README](./iam-client-mobile-demo/README.md) |

## 快速启动

### 1. 启动认证中心

依赖 MySQL 8 + Redis，先导入建表脚本：

```bash
mysql -u root -p < iam-authorization-server/src/main/resources/schema.sql
```

修改 `iam-authorization-server/src/main/resources/application.yml` 中的数据库 / Redis 连接后启动：

```bash
cd iam-authorization-server
mvn spring-boot:run
```

管理后台：http://localhost:9000/admin （账号 `admin / 123456`）

### 2. 启动门户（前后端分离）

```bash
cd iam-portal-service && mvn spring-boot:run   # http://localhost:8080  门户 BFF
cd iam-portal-web && node server.js       # http://localhost:8000  门户前端
```

### 3. 启动演示项目（按需）

```bash
cd iam-client-web-demo     && node server.js   # http://localhost:8081  传统 Web 应用
cd iam-client-device-demo  && node server.js   # http://localhost:8082  设备码
cd iam-client-mobile-demo  && node server.js   # http://localhost:8083  移动应用 / SPA
```

Node.js 演示项目均零依赖，仅需 Node.js；Java 演示项目需要 Maven。

## 启动顺序

1. **MySQL + Redis**（依赖）
2. **iam-authorization-server**（9000）：其他服务通过 OIDC discovery 获取端点配置
3. **iam-portal-service**（8080）：启动时从认证中心拉取 OIDC 配置
4. **iam-portal-web**（8000）：前端纯静态
5. 各业务系统 Demo（8081 / 8082 / 8083）：按需启动

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

客户端配置详见 [schema.sql](./iam-authorization-server/src/main/resources/schema.sql)，对接方式见各演示项目 README。

## 核心特性

- **OAuth2 / OIDC 完整协议**：授权码、密码、客户端模式、设备码、刷新令牌
- **PKCE 支持**：Public Client 强制启用，Confidential Client (portal-app) 也启用
- **双向 SSO**：门户 ↔ 客户端互认登录态，`prompt=none` 静默授权
- **Opaque Token**：Access Token / Refresh Token 均为 Opaque，撤销即删 Redis key
- **JWT ID Token**：RS256 签名，携带用户 authorities
- **在线用户与会话管理**：按用户 / 按 SSO 会话强制下线，层级视图展示
- **管理后台**：用户、客户端、授权记录、在线管理、运行监控
- **前后端分离门户**：iam-portal-web + iam-portal-service BFF 架构
- **多环境配置**：dev / local / prod 通过 `spring.profiles.active` 切换

## 设计文档

- [统一认证管理平台设计说明书](./docs/统一认证管理平台设计说明书.md)（V4.0 完整版，整合 V3.1 基线 + OIDC/PKCE SSO + 在线用户与会话管理 + 测试方案）
