# OAuth2 设备码授权演�?(RFC 8628)

最精简的设备码流程演示，适合无浏览器或输入受限的设备（智能电�?/ IoT 终端 / CLI 工具）�?

- 端口：`8082`
- 依赖：零依赖，仅 Node.js 内置模块
- 角色�?*Public Client**（无 client_secret�?

## 快速开�?

### 前置依赖

启动 `iam-authorization-server` (9000)�?

### 启动

```bash
node server.js
```

访问 http://localhost:8082

## 演示流程

```
�?请求设备�? �? �?用户授权  �? �?轮询�?Token  �? �?访问资源
```

1. 首页自动发起设备码请�?�?展示用户�?
2. 在另一设备浏览器访问授权地址 (`http://localhost:9000/activate`)，输入用户码
3. 登录 (`user/123456`) �?授权确认
4. 本页面自动轮询，授权成功后获�?Token
5. 点击按钮调用通讯�?API / UserInfo / 刷新 Token / 验证 Token

## 客户端配�?

| 参数 | �?|
|------|------|
| client_id | `device-app` |
| 认证方式 | `none` (Public Client, 无密�? |
| 授权类型 | `device_code`, `refresh_token` |
| scopes | `openid profile email` |

> **说明**：设备码流程通过自定�?`DeviceCodeGrantAuthenticationProvider` 签发 id_token（替�?SAS 默认 Provider），因此 scopes 可包�?`openid`。OIDC 用户信息也可通过 `/userinfo` 端点�?access_token 获取�?

## 页面说明

| 路径 | 说明 |
|------|------|
| `GET /` | 首页，已授权则展示功能入口，未授权跳�?/start |
| `GET /start` | 发起设备码请求，跳转到等待授权页 |
| `GET /device` | 展示用户�?+ 轮询状�?|
| `GET /api-demo` | �?access_token 调用 /biz/clients/mine (三方客户端预期被�?403, 合并单服�?:9000) |
| `GET /userinfo-demo` | �?access_token 调用 /userinfo |
| `GET /refresh-demo` | �?refresh_token 换新 token |
| `GET /introspect-demo` | 调用 /oauth2/introspect 验证 token |
| `GET /logout` | 吊销 token + 清除会话 |

## 设备码流程详�?

```
设备�?                     用户手机/PC                   认证中心
  �?                          �?                           �?
  �?�?POST /oauth2/device/code �?                           �?
  �?───────────────────────────────────────────────────�?�?
  �?                          �?                           �?
  �?�?返回 device_code + user_code + verification_uri     �?
  �?◄─────────────────────────────────────────────────── �?
  �?                          �?                           �?
  �?�?显示 user_code + 二维�? �?                           �?
  �?                          �?                           �?
  �?                          �?�?访问 /activate?user_code= �?
  �?                          �?──────────────────────────�?�?
  �?                          �?                           �?
  �?                          �?�?检�?SSO 状�?             �?
  �?                          �?  ├─ 已登�?�?自动确认       �?
  �?                          �?  └─ 未登�?�?登录后确�?    �?
  �?                          �?                           �?
  �?�?轮询 POST /oauth2/token (grant_type=device_code)     �?
  �?───────────────────────────────────────────────────�?�?
  �?                          �?                           �?
  �?�?返回 access_token + id_token                          �?
  �?◄─────────────────────────────────────────────────── �?
```

## 与其他客户端的差�?

| 特�?| oa-web-app / oa-h5-app | device-app |
|------|----------------------|-------------|
| 授权入口 | `/oauth2/authorize` | `/oauth2/device/code` |
| 用户交互 | 浏览器直接登�?| 在其他设备上输入 user_code |
| 客户端类�?| Confidential / Public (PKCE) | Public (�?PKCE) |
| Token 获取 | 浏览器回调换 Token | 设备轮询 Token 端点 |
| redirect_uri | 必须 | 不需�?|

## 相关文档

- [概要设计](../../docs/概要设计.md) / [详细设计](../../docs/详细设计.md) / [接口文档](../../docs/接口文档.md)
- [认证中心 README](../../server/iam-authorization-server/README.md)
