# OAuth2 授权码登录演示 (Confidential Client)

传统 Web 应用接入示例，演示授权码模式 + 密码模式。全程页面操作，直观可视。

- 端口：`8081`
- 依赖：零依赖，仅 Node.js 内置模块
- 角色：**Confidential Client**（持有 client_secret）

## 快速开始

### 前置依赖

启动 `iam-authorization-server` (9000)。

### 启动

```bash
node server.js
```

访问 http://localhost:8081

## 演示流程

```
① 发起授权  →  ② 登录确认  →  ③ 回调取码  →  ④ 换取 Token  →  ⑤ 访问资源
```

1. 首页点击"开始授权登录" → 跳转授权服务器
2. 登录 (`user/123456`) → 授权确认页点"允许"
3. 回调到本服务 → 服务端自动用 code 换 token
4. 展示 token 响应 + id_token 解码
5. 点击按钮调用通讯录 API / UserInfo / 刷新 Token

## 客户端配置

| 参数 | 值 |
|------|------|
| client_id | `web-app` |
| 认证方式 | `client_secret_basic`, `client_secret_post` (Confidential Client) |
| 授权类型 | `authorization_code`, `refresh_token`, `password` |
| scopes | `openid profile email read write` |
| redirect_uri | `http://localhost:8081/callback` |

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页，发起授权 |
| `GET /callback` | 接收回调，服务端换 token，展示结果 |
| `GET /api-demo?token=xxx` | 用 token 调用 /api/contacts (位于独立资源服务 :9010) |
| `GET /userinfo-demo?token=xxx` | 用 token 调用 /userinfo |
| `GET /refresh-demo?token=xxx` | 用 refresh_token 换新 token |
| `GET /return-to-portal` | SSO 返回门户：构造 `prompt=none` 静默授权 URL |
| `GET /portal-sso-callback` | SSO 回调：处理 `self-silent` 类型，用 code_verifier 换 Token |
| `GET /logout` | 吊销 token + 清除会话 + 跳转认证中心 logout |

## SSO 返回门户机制

从 web-app 返回门户时，通过 `/return-to-portal` 端点实现 SSO：

1. 构造 `prompt=none` 静默授权 URL（client_id=portal-app）
2. 跳转到认证中心 `/oauth2/authorize`
3. 回调到 `/portal-sso-callback`
4. 若有 SSO Session → 拿到 code → 正常换 Token → 创建 PORTAL_SESSION
5. 若无 SSO Session → 返回 `login_required` → 转正常登录流程

回调类型 `self-silent` 允许客户端用 code_verifier 完成 Token 交换。

## 为什么服务端换 token

client_secret 不能暴露给浏览器，所以 code → token 的交换在 Node.js 服务端完成。这也是标准授权码流程的安全设计。

## 相关文档

- [统一认证管理平台设计说明书](../../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO 设计）
- [认证中心 README](../../iam-authorization-server/README.md)
