# Portal App — 门户前端

统一认证平台的门户前端应用，纯静态服务（零依赖 Node.js）。展示客户端列表，引导用户通过 SSO 单点登录到各业务系统。

- 端口：`8000`
- 依赖：仅 Node.js 内置模块（`http` / `url`）
- 角色：**纯前端**，不持有 client_secret，所有 OAuth2 流程委托 iam-portal-service (BFF)

## 架构定位

```
[浏览器] ──► iam-portal-web (8000, 前端)
                 │
                 │  代理 /api/* 请求（透传 PORTAL_SERVER_SESSION Cookie）
                 ▼
             iam-portal-service (8080, BFF)
                 │
                 │  OAuth2 授权码 + PKCE
                 ▼
             iam-authorization-server (9000, 认证中心)
```

## 快速开始

### 前置依赖

1. 启动 `iam-authorization-server` (9000)
2. 启动 `iam-portal-service` (8080)

### 启动

```bash
node server.js
```

访问 http://localhost:8000

## 页面与路由

| 路径 | 说明 |
|------|------|
| `GET /` | 门户首页：未登录显示登录卡片，已登录显示客户端列表 |
| `GET /login` | 302 跳转到 iam-portal-service `/api/auth/login` 触发 OAuth2 授权码流程 |
| `GET /logout` | 302 跳转到 iam-portal-service `/api/auth/logout` 触发 OIDC RP-Initiated Logout |
| `GET /logged-out` | 登出后落地页（认证中心重定向回此处） |
| `GET /api/*` | 代理到 iam-portal-service (8080)，透传 `PORTAL_SERVER_SESSION` Cookie |

## 客户端列表来源

通过 `GET /api/clients` 调用 iam-portal-service，iam-portal-service 再调用认证中心的 `GET /api/public/clients` 获取：

- 跳过 `portal-app` 自身
- 跳过设备码客户端（`device-app`）
- 仅返回支持授权码模式的客户端（`web-app` / `mobile-app`）

每个客户端卡片点击后跳转客户端首页（**不直接生成授权 URL**），由客户端自行检测 session 并决定是否发起授权流程。

## 关键设计

- **不持有 client_secret**：纯前端，token 交换在 iam-portal-service 完成
- **Cookie 隔离**：iam-portal-web 不操作 Cookie，依赖 iam-portal-service 的 `PORTAL_SERVER_SESSION`
- **代理透传**：`/api/*` 请求透传 Cookie 到 iam-portal-service，保持会话连续性
- **CORS**：iam-portal-service 配置允许 `http://localhost:8000` 跨域携带 Cookie

## 相关文档

- [iam-portal-service README](../iam-portal-service/README.md)
- [统一认证管理平台设计说明书](../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO 设计）
