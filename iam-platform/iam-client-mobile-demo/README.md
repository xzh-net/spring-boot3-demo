# OAuth2 授权码 + PKCE 演示 (Public Client)

模拟原生移动应用 (iOS/Android) 或无后端纯前端 SPA (Vue/React) 的接入场景。通过 PKCE 防止授权码拦截攻击，无需 client_secret。

- 端口：`8083`
- 依赖：零依赖，仅 Node.js 内置模块 (含 `crypto` 用于 PKCE 计算)
- 角色：**Public Client + PKCE**（无 client_secret）

## 快速开始

### 前置依赖

启动 `iam-authorization-server` (9000)。

### 启动

```bash
node server.js
```

访问 http://localhost:8083

## 演示流程

```
① 发起授权(+code_challenge) → ② 登录确认 → ③ 回调取码 → ④ 换取 Token(+code_verifier) → ⑤ 访问资源
```

1. 首页点击"开始 PKCE 授权登录" → 自动生成 `code_verifier` / `code_challenge`，跳转授权服务器
2. 登录 (`user/123456`) → 授权确认页点"允许"
3. 回调到本服务 → 按 `state` 取出 `code_verifier`，连同 `code` 换取 token
4. 展示 token 响应 + id_token 解码
5. 点击按钮调用通讯录 API / UserInfo / 内省 Token / 重新授权

## 客户端配置

| 参数 | 值 |
|------|------|
| client_id | `mobile-app` |
| 认证方式 | `none` (Public Client, 无密钥) |
| 授权类型 | `authorization_code`, `refresh_token` |
| scopes | `openid profile email read write` |
| requireProofKey | `true` (强制 PKCE) |
| redirect_uri | `http://localhost:8083/callback` (演示用；原生 App 应为自定义 scheme) |

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页，发起 PKCE 授权 |
| `GET /callback` | 接收回调，用 code + code_verifier 换 token，展示结果 |
| `GET /api-demo` | 用 access_token 调用 /api/contacts (位于独立资源服务 :9010) |
| `GET /userinfo-demo` | 用 access_token 调用 /userinfo |
| `GET /introspect-demo` | 调用 /oauth2/introspect 验证 token |
| `GET /reauth` | 静默重新授权 (清旧 session 后重走授权码流程) |
| `GET /return-to-portal` | SSO 返回门户：构造 `prompt=none` 静默授权 URL |
| `GET /portal-sso-callback` | SSO 回调：处理 `self-silent` 类型，用 code_verifier 换 Token |
| `GET /logout` | 吊销 token + 清除会话 |

## 与 web-app 的差异 (仅 PKCE 相关)

| 环节 | web-app (Confidential) | mobile-app (Public + PKCE) |
|------|------------------------|----------------------------|
| 授权 URL | — | 多带 `code_challenge` + `code_challenge_method=S256` |
| 换 token | 带 `Authorization: Basic` (client_secret) | 带 `code_verifier`，无 client_secret |
| refresh_token | ✅ 签发 | ❌ 不签发 (RFC 8252 安全策略) |
| token 过期续期 | 用 refresh_token | 走 `/reauth` 静默重新授权 |

> **为什么没有 refresh_token？** Public Client 无法安全存储 refresh_token，SAS 依 RFC 8252 不予签发。access_token 过期后点击"重新授权"，若授权服务器 session 仍有效，整个过程无需重新登录（silent renew）。

## SSO 返回门户机制

Public Client 不签发 refresh_token，通过 `/return-to-portal` 端点实现 SSO 返回：

1. 跳转到认证中心 `/oauth2/authorize?client_id=portal-app&prompt=none`
2. 回调到 `/portal-sso-callback`
3. 若有 SSO Session → 拿到 code → 正常换 Token → 创建 PORTAL_SESSION
4. 若无 SSO Session → 返回 `login_required` → 转正常登录流程
5. 回调类型 `self-silent` 允许客户端用 code_verifier 完成 Token 交换

## PKCE 计算说明

```
1. 生成 code_verifier (32 字节随机数, Base64URL = 43 字符)
2. 计算 code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
3. 授权请求带 code_challenge + code_challenge_method=S256
4. Token 请求带 code_verifier 明文
5. 认证中心校验 SHA256(code_verifier) == code_challenge，一致则签发 Token
```

## 相关文档

- [统一认证管理平台设计说明书](../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含 OIDC/PKCE SSO 设计）
- [认证中心 README](../iam-authorization-server/README.md)
