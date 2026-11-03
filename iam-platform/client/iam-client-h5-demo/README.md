# OA H5 演示（iam-client-h5-demo）

纯 Web 应用的 **H5 形态**演示端 —— 对接方式与 web 版（8081）**本质一模一样**，差异只在 UI 壳（手机模拟器）。

| 项 | 值 |
|---|---|
| 端口 | `8084` |
| client_id | `oa-h5-app`（机密客户端, `client_secret_basic`） |
| secret | `123456` |
| 授权模式 | 授权码 + 刷新令牌（**强制 PKCE** `requireProofKey=true`, S256） |
| redirect_uri | `http://localhost:8084/callback` |
| 返回门户回调 | `http://localhost:8084/portal-sso-callback`（prompt=none 静默回流） |

## 页面

- **手机模拟器主页**：居中手机壳 + 状态栏 + 硬编码业务模块（请假管理 / 报销审核 / 审批中心 / 考勤打卡 / 通讯录）
- 未登录点模块 → 发起授权码登录（9000 有 SSO 会话则**免登**，首次弹同意页）
- 登录后点模块 → 面板显示该模块 mock 数据（`/api/module` 由会话令牌保护, 未登录 401）
- 底部：令牌信息 / 退出登录 / 🏠 返回门户（prompt=none，SSO 失效则转门户正常登录）

## 启动

```bash
cd client/iam-client-h5-demo && node server.js   # :8084
```

也可用手机访问 `本机IP:8084`（同网段）。`start-all.ps1` 已纳管本服务。
