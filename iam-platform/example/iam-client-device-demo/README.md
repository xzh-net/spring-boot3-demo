# OAuth2 设备码授权演示 (RFC 8628)

最精简的设备码流程演示，适合无浏览器或输入受限的设备（智能电视 / IoT 终端 / CLI 工具）。

- 端口：`8082`
- 依赖：零依赖，仅 Node.js 内置模块
- 角色：**Public Client**（无 client_secret）

## 快速开始

### 前置依赖

启动 `iam-authorization-server` (9000)。

### 启动

```bash
node server.js
```

访问 http://localhost:8082

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

> **说明**：设备码流程通过自定义 `DeviceCodeGrantAuthenticationProvider` 签发 id_token（替换 SAS 默认 Provider），因此 scopes 可包含 `openid`。OIDC 用户信息也可通过 `/userinfo` 端点用 access_token 获取。

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页，已授权则展示功能入口，未授权跳转 /start |
| `GET /start` | 发起设备码请求，跳转到等待授权页 |
| `GET /device` | 展示用户码 + 轮询状态 |
| `GET /api-demo` | 用 access_token 调用 /api/contacts (位于独立资源服务 :9010) |
| `GET /userinfo-demo` | 用 access_token 调用 /userinfo |
| `GET /refresh-demo` | 用 refresh_token 换新 token |
| `GET /introspect-demo` | 调用 /oauth2/introspect 验证 token |
| `GET /logout` | 吊销 token + 清除会话 |

## 设备码流程详解

```
设备端                      用户手机/PC                   认证中心
  │                           │                            │
  │ ① POST /oauth2/device/code │                            │
  │ ───────────────────────────────────────────────────► │
  │                           │                            │
  │ ② 返回 device_code + user_code + verification_uri     │
  │ ◄─────────────────────────────────────────────────── │
  │                           │                            │
  │ ③ 显示 user_code + 二维码  │                            │
  │                           │                            │
  │                           │ ④ 访问 /activate?user_code= │
  │                           │ ──────────────────────────► │
  │                           │                            │
  │                           │ ⑤ 检测 SSO 状态              │
  │                           │   ├─ 已登录 → 自动确认       │
  │                           │   └─ 未登录 → 登录后确认     │
  │                           │                            │
  │ ⑥ 轮询 POST /oauth2/token (grant_type=device_code)     │
  │ ───────────────────────────────────────────────────► │
  │                           │                            │
  │ ⑦ 返回 access_token + id_token                          │
  │ ◄─────────────────────────────────────────────────── │
```

## 与其他客户端的差异

| 特性 | web-app / mobile-app | device-app |
|------|----------------------|-------------|
| 授权入口 | `/oauth2/authorize` | `/oauth2/device/code` |
| 用户交互 | 浏览器直接登录 | 在其他设备上输入 user_code |
| 客户端类型 | Confidential / Public (PKCE) | Public (无 PKCE) |
| Token 获取 | 浏览器回调换 Token | 设备轮询 Token 端点 |
| redirect_uri | 必须 | 不需要 |

## 相关文档

- [统一认证管理平台设计说明书](../../docs/统一认证管理平台设计说明书.md)（V4.0 完整版，含设备码模式设计）
- [认证中心 README](../../iam-authorization-server/README.md)
