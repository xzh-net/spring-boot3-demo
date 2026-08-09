# OAuth2 设备码授权演示

最精简的设备码流程演示 (RFC 8628)，适合无浏览器或输入受限的设备。

## 快速开始

```bash
node server.js
```

访问 http://localhost:8081

## 演示流程

```
① 请求设备码  →  ② 用户授权  →  ③ 轮询取 Token  →  ④ 访问资源
```

1. 首页自动发起设备码请求 → 展示用户码
2. 在另一设备浏览器访问授权地址 (`http://localhost:9000/activate`)，输入用户码
3. 登录 (`user/123456`) → 授权确认
4. 本页面自动轮询，授权成功后获取 Token
5. 点击按钮调用通讯录 API / UserInfo / 刷新 Token / 验证 Token

## 客户端配置

| 参数 | 值 |
|------|------|
| client_id | `device-app` |
| 认证方式 | `none` (Public Client, 无密钥) |
| 授权类型 | `device_code`, `refresh_token` |
| scopes | `openid profile email read` |

> **说明**: 设备码流程通过自定义 `DeviceCodeGrantAuthenticationProvider` 签发 id_token（替换 SAS 默认 Provider），因此 scopes 可包含 `openid`。OIDC 用户信息也可通过 `/userinfo` 端点用 access_token 获取。

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页, 已授权则展示功能入口, 未授权跳转 /start |
| `GET /start` | 发起设备码请求, 跳转到等待授权页 |
| `GET /device` | 展示用户码 + 轮询状态 |
| `GET /api-demo` | 用 access_token 调用 /api/contacts |
| `GET /userinfo-demo` | 用 access_token 调用 /userinfo |
| `GET /refresh-demo` | 用 refresh_token 换新 token |
| `GET /introspect-demo` | 调用 /oauth2/introspect 验证 token |
| `GET /logout` | 吊销 token + 清除会话 |

## 依赖

**零依赖**，仅使用 Node.js 内置模块。
