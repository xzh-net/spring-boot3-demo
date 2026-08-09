# OAuth2 授权码登录演示

最精简的授权码流程演示，全程页面操作，直观可视。

## 快速开始

```bash
node server.js
```

访问 http://localhost:8080

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
| redirect_uri | `http://localhost:8080/callback` |

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页, 发起授权 |
| `GET /callback` | 接收回调, 服务端换 token, 展示结果 |
| `GET /api-demo?token=xxx` | 用 token 调用 /api/contacts |
| `GET /userinfo-demo?token=xxx` | 用 token 调用 /userinfo |
| `GET /refresh-demo?token=xxx` | 用 refresh_token 换新 token |

## 为什么服务端换 token

client_secret 不能暴露给浏览器，所以 code → token 的交换在 Node.js 服务端完成。
这也是标准授权码流程的安全设计。

## 依赖

**零依赖**，仅使用 Node.js 内置模块。
