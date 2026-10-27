# iam-platform — 统一认证管理平台（单服务合并形态）

基于 Spring Authorization Server 1.4.1 的 OAuth2 / OIDC 统一认证管理平台。**平台已合并为单服务单库**：原认证中心 (`iam-authorization-server`) 与原资源中心 (`iam-resource-service`) 合并为 **9000 单服务**（包结构 `net.xzh.iam.{common,auth,resource}`），单 MySQL 库 **`iam`**（**16 表**，零租户）。

**权限模型为双维**：令牌业务权限码 = **用户 RBAC 码 ∩ 客户端授权范围 (scope) 展开码**，自省层 fail-closed 注入，任一维缺口即 403；签发前再做一次同源判定实现**混合登录隔离**（门户 / 管理端用户不跨端登录）。

---

## 一、目录结构总览

```text
iam-platform/
├── README.md                           # 本文件：结构 + 端口 + 启动 + 架构 + 更新日志 + 待办
│
├── server/                             # ──【服务端】Java · Spring Boot 3.4──
│   └── iam-authorization-server/       #   :9000 单服务（协议端点 + 三域管理/业务 API，包 net.xzh.iam.*）
│       └── src/main/
│           ├── java/net/xzh/iam/       #   common（基建）/ auth（协议）/ resource（业务+准入）
│           └── resources/              #   application*.yml + static/login.html
│
├── bff/                                # ──【体验面】Java · OAuth2 Client，无库──
│   ├── iam-admin-bff/                  #   :8085  管理后台 BFF（admin-app 授权码登录 + Bearer 透传）
│   └── iam-portal-bff/                 #   :8080  门户 BFF（portal-app，Confidential + PKCE）
│
├── web/                                # ──【前端】纯静态站，无逻辑──
│   ├── iam-admin-web/                  #   :8001  管理后台（用户/角色/权限/资源准入/客户端/授权范围/应用/在线）
│   └── iam-portal-web/                 #   :8000  门户（客户端 SSO 卡片）
│
├── client/                             # ──【客户端示例】Node.js 零依赖 OAuth2 接入演示──
│   ├── iam-client-web-demo/            #   :8081  授权码 + 密码模式（web-app）
│   ├── iam-client-device-demo/         #   :8082  设备码 RFC 8628（device-app）
│   └── iam-client-mobile-demo/         #   :8083  授权码 + PKCE（mobile-app）
│
├── sql/                                # ──【数据库脚本】单库 iam──
│   ├── iam.sql                         #   合并基线（16 表 + 全部种子，新库初始化唯一入口）
│   └── migration/                      #   既有库增量升级脚本（V6.2–V6.14）
│
├── docs/                               # ──【文档】设计说明、改造清单与改造记录──
├── start-all.ps1 / start-all.bat       # ──【脚本】一键启停核心服务──
└── 待处理.txt
```

---

## 二、端口规划

```text
8000 ~ 8009   前端静态站段     portal-web=8000  admin-web=8001
8080 ~ 8089   BFF 与演示段     portal-bff=8080  admin-bff=8085  demo=8081/8082/8083
9000          服务端核心       iam-authorization-server（唯一服务，协议端点 + 管理/业务 API）
```

> 数据库 / Redis 默认指向 `192.168.31.161`（MySQL `iam` 库、Redis db1），在
> `server/iam-authorization-server/src/main/resources/application-{profile}.yml` 中调整。

---

## 三、模块职责

### 服务端（单服务）

| 模块 | 端口 | 库 | 职责 |
|---|---|---|---|
| iam-authorization-server | 9000 | `iam` | OAuth2/OIDC 协议运行时（授权码、密码、设备码、刷新）+ 三域管理 API `/api/admin/**` + 门户 API `/api/public/**` + RBAC 角色权限 + 端点准入裁决 + 签发准入 |

### 体验面 / 前端 / 客户端示例

| 模块 | 端口 | 职责 |
|---|---|---|
| iam-admin-bff | 8085 | 管理 BFF：OAuth2 Client(admin-app) 授权码 SSO 登录，Bearer 透传管理 API |
| iam-portal-bff | 8080 | 门户 BFF：OAuth2 Client(portal-app) Confidential + PKCE，独立会话与 RP-Initiated 登出 |
| iam-admin-web | 8001 | 管理后台静态站（含只读「授权范围」页与只读「资源准入」页） |
| iam-portal-web | 8000 | 门户静态站（客户端列表与 SSO 跳转卡片） |
| iam-client-*-demo | 8081/8082/8083 | 三种 OAuth2 接入姿势演示（授权码+密码 / 设备码 / PKCE） |

---

## 四、快速启动

### 1. 初始化数据库（单库 `iam`）

依赖 MySQL 8 + Redis。导入合并基线（16 表，零租户）：

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam DEFAULT CHARSET utf8mb4"
mysql -u root -p iam < sql/iam.sql
# 既有库升级用 sql/migration/（V6.2–V6.14），新库无需执行
```

### 2. 启动核心服务（顺序固定）

```bash
cd server/iam-authorization-server && mvn spring-boot:run     # :9000  必须最先起
cd bff/iam-admin-bff        && mvn spring-boot:run     # :8085  依赖 9000（启动时拉 OIDC discovery）
cd web/iam-admin-web        && node server.js          # :8001  管理后台前端
```

> **启动顺序**：必须先 9000 后 8085 —— BFF 启动时要拉 `http://localhost:9000/.well-known/openid-configuration`，9000 未就绪会 `Connection refused` 直接退出。
> 一键启停：`powershell -ExecutionPolicy Bypass -File .\start-all.ps1`

### 3. 门户与演示项目（按需）

```bash
cd bff/iam-portal-bff && mvn spring-boot:run   # :8080
cd web/iam-portal-web && node server.js         # :8000
cd client/iam-client-web-demo    && node server.js   # :8081
cd client/iam-client-device-demo && node server.js   # :8082
cd client/iam-client-mobile-demo && node server.js   # :8083
```

### 4. 默认账号

| 账号 | 密码 | 角色 | 用途 |
|---|---|---|---|
| `admin` | `123456` | `ADMIN`（持 16 个管理域权限码） | 管理后台 |
| `user` | `123456` | `PORTAL`（持 1 个门户权限码） | 门户 / 演示项目 |

### 5. 默认客户端

| client_id | 授权模式 | 持有 scope | 适用 |
|---|---|---|---|
| `admin-app` | 授权码 + 刷新 | `admin.full`（16 码） | 管理后台 BFF |
| `portal-app` | 授权码 + 刷新（PKCE） | `portal.profile`（1 码） | 门户 BFF |
| `web-app` | 授权码 / 密码 | `third.profile`（空映射） | 传统 Web 应用演示 |
| `device-app` | 设备码 | 无业务 scope | 电视 / IoT / CLI |
| `mobile-app` | 授权码 + PKCE | 无业务 scope | 原生 App / SPA |

---

## 五、核心架构：双维权限控制

### 裁决链（四层，全部 fail-closed）

```text
① 签发准入  /oauth2/authorize        用户码 ∩ 客户端scope码 为空 → 拒发码 → 登录页越权提示
② 令牌自省  RbacAuthorities...        用户码 ∩ 客户端scope码 = 注入的业务权限码
③ 端点准入  iam_endpoint_policy       请求(方法+路径) → 所需权限码 ∈ 令牌码 才放行
④ 域白名单  已退役                    客户端维度隔离由 ①② 的 scope 交集承担
```

### 数据模型（16 表，按职责分组）

| 分组 | 表 |
|---|---|
| 协议数据 | `oauth2_registered_client` / `oauth2_authorization_record` / `oauth2_authorization_consent` |
| 身份与凭据 | `sys_user` / `iam_external_identity` |
| RBAC（用户维） | `sys_role` / `sys_user_role` / `sys_permission` / `sys_role_permission` |
| 授权范围（客户端维） | `sys_scope` / `sys_scope_permission` |
| 端点准入 | `iam_endpoint_policy` |
| 平台资产 | `iam_application` / `iam_application_channel` / `iam_org` / `iam_app_authorization` |

### 字典与准入的写入语义（重要）

| 对象 | 谁能写 | 说明 |
|---|---|---|
| `sys_scope` / `sys_scope_permission` | **仅 `sql/iam.sql` 种子** | 只读字典，页面只展示 |
| `sys_permission` | 仅种子（页面可维护码本身） | 业务分类用 `remark` 前缀 `【管理端】`/`【门户】` 标记 |
| `iam_endpoint_policy` | **仅 `sql/iam.sql` 种子 + 启动自扫描补缺** | 页面只读无 CRUD；扫描只补新端点、**不回写** authority、不剪除；精确权限码权威=种子 |
| `oauth2_registered_client.scopes` | 管理端「客户端管理」页 | 标准 Spring 列作客户端↔scope 连接表 |

> **新增一个受管控接口的三步**：`sys_permission` 加码（若有新码）→ 角色 / scope 绑定 → `iam_endpoint_policy` 种子加端点行写入权限码 → 重载 DB + 重启。
> 控制器方法须位于 `controller.admin|portal|third` 包下才会被扫描入表，否则落认证档。

---

## 六、关键设计裁定

1. **fail-closed 是默认姿态**：签发、自省、端点准入三层任一环缺口即拒绝，无"猜解放行"路径。
2. **双维正交**：用户维（角色→权限码，细粒度）与客户端维（scope→权限码，粗粒度）收敛到同一张 `sys_permission` 字典后取交集，不新建第二权威。
3. **字典演进走 SQL 种子**：`sys_scope` 等只读字典不提供页面写入口，避免"页面"与"种子"双演进路径打架。
4. **已退役的旧机制**（本轮移除，勿再引用）：`iam_client_policy`（登录边界策略）、`AuthServerProperties`（客户端白名单）、`ADMIN_SERVICE_TOKEN`/`PORTAL_SERVICE_TOKEN`（粗档常量与 M2M 分支）、`sys_user.user_label`（标签列与降级猜测）。

---

## 七、设计文档

- [统一认证管理平台设计说明书](./docs/统一认证管理平台设计说明书.md)
- [数据模型设计](./docs/数据模型设计.md)（历史快照，现行基线以 `sql/iam.sql` 为准）
- [改造记录](./docs/改造记录.md)（按日期倒序的完整演进日志）
- [改造清单 - 一级框架](./docs/改造清单-一级框架.md) / [二级应用](./docs/改造清单-二级应用.md)

---

## 八、更新日志

| 日期 | 类型 | 内容 |
|---|---|---|
| 2026-10-27 | 删除 | `iam_endpoint_policy` 的 `domain`/`source` 两列及其页面增删改，表收归「只读 + 唯一写入方=启动自扫描」 |
| 2026-10-27 | 删除 | `sys_permission.domain`（业务分类改用 `remark` 前缀 `【管理端】`/`【门户】`）、`sys_scope.domain`（由 scope 码前缀自表达） |
| 2026-10-27 | 删除 | 客户端信任闸 `clientWhitelistGate`、`AuthServerProperties` 整类、`application.yml` 三段白名单配置 |
| 2026-10-27 | 删除 | 粗档常量 `ADMIN_SERVICE_TOKEN`/`PORTAL_SERVICE_TOKEN` 及 M2M 服务令牌分支；5 行端点粗档迁为细粒度码 |
| 2026-10-27 | 删除 | `sys_user.user_label` 列及其校验、展示、"降级猜测"逻辑（登录异常改为降级空角色 fail-closed） |
| 2026-10-27 | 增加 | 签发准入 `IssuanceAdmissionService` + `AuthorizeIssuanceFilter`（混合登录隔离），登录页按 `error=access_denied` 区分越权与密码错误提示 |
| 2026-10-27 | 增加 | 权限码 `policy:read`/`policy:write`/`portal:client:read`（承接原粗档端点），权限码总数 14→17 |
| 2026-10-27 | 修改 | 双服务遗留命名清理：`PortalUserDetailsService`→`PlatformUserDetailsService`、`portalDaoProvider`→`platformDaoProvider`、`PORTAL_CONTEXT_KEY`→`OAUTH2_CONTEXT_KEY` |
| 2026-10-27 | 修改 | 资源准入 / 授权范围 / 权限管理三页文案精简并集中到顶部，两只读页移除刷新按钮，菜单「授权范围」与「应用管理」位置互换 |
| 2026-10-27 | 修改 | README 按当前项目重写；SQL 脚本从 `src/main/resources` 迁出至 `sql/` |
| 2026-10-26 | 修改 | 数据库 / Redis 地址 `192.168.43.161` → `192.168.31.161`（`application-dev.yml` / `application-local.yml`） |
| 2026-10-26 | 修复 | `admin-app` 密钥异常态恢复为基线 `123456`（经 SQL 直写 + 清 Redis `oauth2:client:*` 缓存） |
| 2026-10-25 | 增加 | 双维权限控制：`sys_scope`/`sys_scope_permission` 两表、`ScopeService`、`AdminScopeController`(只读 GET)、只读页「授权范围」；自省层按「用户码 ∩ 客户端 scope 码」注入业务权限码 |
| 2026-10-25 | 删除 | `iam_client_policy` 表及其 8 个 Java（ClientPolicy 族 / AuthorizePolicyFilter / 两个 PolicyAware provider）、`policy.html`、迁移 V6.1 与 V6.10 |
| 2026-10-25 | 修改 | 「客户端管理」页 scopes 改为授权范围勾选 + 保留 Scope 双块；「权限管理」页增加「所属授权范围」列 |

---

## 九、待办清单

1. **YAML 配置分类**：整理当前项目存在的硬编码，按 `application-auth.yaml` / `application-resource.yaml` 的格式，拆分到不同的配置文件中。
