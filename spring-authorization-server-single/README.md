# 统一认证中心

基于 Spring Authorization Server 1.4.1 的单体统一认证中心，提供 OAuth2 / OIDC 能力，配套 3 个对接演示项目，覆盖主流接入场景。

## 项目结构

| 项目 | 类型 | 端口 | 说明 | 文档 |
|------|------|------|------|------|
| `spring-authorization-server` | 服务端 (Java) | 9000 | 认证中心主体，含管理后台、OAuth2 端点、资源 API | [README](./spring-authorization-server/README.md) |
| `oauth2-callback-web-app` | 演示 (Node) | 8080 | 授权码模式 — 传统 Web 应用 (Confidential Client) | [README](./oauth2-callback-web-app/README.md) |
| `oauth2-callback-device-app` | 演示 (Node) | 8081 | 设备码模式 — 输入受限设备 (RFC 8628) | [README](./oauth2-callback-device-app/README.md) |
| `oauth2-callback-mobile-app` | 演示 (Node) | 8082 | 授权码 + PKCE — 移动应用 / SPA (Public Client) | [README](./oauth2-callback-mobile-app/README.md) |

## 快速启动

### 1. 启动认证中心

依赖 MySQL 8 + Redis，先导入建表脚本：

```bash
mysql -u root -p < spring-authorization-server/src/main/resources/schema.sql
```

修改 `spring-authorization-server/src/main/resources/application.yml` 中的数据库 / Redis 连接后启动：

```bash
cd spring-authorization-server
mvn spring-boot:run
```

管理后台：http://localhost:9000/admin （账号 `admin / 123456`）

### 2. 启动演示项目（按需）

```bash
cd oauth2-callback-web-app     && node server.js   # http://localhost:8080  传统 Web 应用
cd oauth2-callback-device-app  && node server.js   # http://localhost:8081  设备码
cd oauth2-callback-mobile-app  && node server.js   # http://localhost:8082  移动应用 / SPA
```

演示项目均零依赖，仅需 Node.js。

## 默认账号

| 账号 | 密码 | 角色 | 用途 |
|------|------|------|------|
| `admin` | `123456` | ROLE_ADMIN | 管理后台 |
| `user` | `123456` | ROLE_USER | 演示项目登录 |

## 默认客户端

| client_id | 模式 | 认证方式 | 适用场景 |
|-----------|------|---------|---------|
| `web-app` | 授权码 + 密码 | client_secret_basic | 传统 Web 应用 |
| `device-app` | 设备码 | none | 电视 / IoT / CLI |
| `mobile-app` | 授权码 + PKCE | none | 原生 App / SPA |
| `service-app` | 客户端模式 | client_secret_basic | 服务间调用 (M2M) |

客户端配置详见 [schema.sql](./spring-authorization-server/src/main/resources/schema.sql)，对接方式见各演示项目 README。
