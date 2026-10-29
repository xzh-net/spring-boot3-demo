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
├── docs/                               # ──【文档】概要/详细设计 · 权限 · 库 · 接口 · 编码 · 操作（7 份）──
├── start-all.ps1 / start-all.bat       # ──【脚本】一键启停核心服务──
└── 待处理.txt
```

---

## 二、端口规划

端口段约定：`8000~8009` 前端静态站 ｜ `8080~8089` BFF 与三方演示 ｜ `9000` 服务端核心。
MySQL / Redis 在 `192.168.31.161`（库 `iam`、Redis db1），改地址见
`server/iam-authorization-server/src/main/resources/application-{profile}.yml`；启动顺序见「四、快速启动」。

| 服务 | 端口 | 入口 URL | 说明 | 备注（进去以后的主要逻辑） |
|---|---|---|---|---|
| **iam-authorization-server**<br>服务端（唯一 Java 服务） | 9000 | `http://localhost:9000` | 认证中心：登录页 + OAuth2/OIDC 协议端点 + 全部业务 API | 直接访问 `/` 或登录页直登，**自动并入门户登录流**（见下方速查③）。登录表单是管理/门户两条流**共用**的，靠签发准入闸按「客户端 × 角色」裁决：portal-app 只放行 PORTAL 用户、admin-app 只放行 ADMIN 用户。`/admin/**`、`/biz/**` 的权限码裁决也在此执行，管理页对其**只读**；另有免令牌测试口 `/permitall/time` |
| **iam-admin-bff** | 8085 | `http://localhost:8085` | 管理端 BFF（OAuth2 Client: admin-app，授权码 + PKCE） | 未登录访问任意路径**自动发起登录**（无自有登录页，表单即 9000 那张），成功返回管理台。**仅管理员可进**：admin-app 持 `admin.full`（16 个管理码）与 ADMIN 角色有交集，普通用户无交集 → 9000 红条拒绝。`/admin/**` 透传 9000（Bearer 只在 BFF 服务端内存附加，token 不出后端）；`/api/current-user` 为 BFF 原生（读本地会话） |
| **iam-admin-web** | 8001 | `http://localhost:8001` | 管理后台前端（node 静态 + 代理） | 未登录访问 → `/login` → 8085 → 9000 登录 → 成功**返回管理台**。**门户用户（user）不可登录**，原因同上：admin-app × PORTAL 角色无交集。页面：用户/角色/权限/客户端/授权管理/在线用户，外加只读「授权范围」「资源准入(48 行)」。node 将 `/admin/**` 与 `/api/**` 代理到 8085 |
| **iam-portal-bff** | 8080 | `http://localhost:8080` | 门户 BFF（OAuth2 Client: portal-app，Confidential + PKCE） | 未登录自动发起登录，成功**返回已登录门户**。**仅普通用户可进**：portal-app 持 `portal.profile`（1 个码）与 PORTAL 角色有交集，admin 无交集 → 9000 红条拒绝。`/api/*` 为 BFF 原生（会话层）；可见应用列表由 BFF **服务端代调** 9000 `/biz/clients/mine` |
| **iam-portal-web** | 8000 | `http://localhost:8000` | 门户前端（node 静态 + 代理） | 未登录：显示新闻动态/通知公告演示数据，登录入口在导航栏右上角。`/login` → 8080 → 9000 登录 → 成功**返回已登录门户**（应用中心卡片）。**管理员（admin）不可登录**，原因同上：portal-app × ADMIN 角色无交集。登录后点应用卡片即 SSO 跳对接应用；node 将 `/api/*` 代理到 8080 |
| **iam-client-web-demo** | 8081 | `http://localhost:8081` | 三方演示：授权码 + PKCE（web-app） | 流程演示：登录 → code 换 token → 调 API → 内省 → 刷新/登出，页面可见真实令牌。web-app 持 `third.profile`（**空映射**）→ 任何账号都能登录（逃逸阀）但令牌 **0 个业务码**；调门户接口 `/biz/clients/mine` 一律 **403** —— fail-closed 现场 |
| **iam-client-device-demo** | 8082 | `http://localhost:8082` | 三方演示：设备码（device-app） | RFC 8628 全流程：取码 → 本页 `/activate` 输入 user_code → 登录 + 同意 → 设备端轮询换票。device-app 为**公开客户端（无密钥）**，须用户同意后才发令牌 |
| **iam-client-mobile-demo** | 8083 | `http://localhost:8083` | 三方演示：移动端 PKCE（mobile-app） | 公开客户端 PKCE 演示：页面**预生成授权链接**（已带 code_challenge），授权码换票。无密钥，靠 PKCE 防授权码拦截 |
| MySQL | 3306 | `192.168.31.161` | 库 `iam`（16 表） | 种子唯一来源 `sql/iam.sql`；字典/准入表的写入语义见「五、核心架构」 |
| Redis | 6379 | `192.168.31.161` | db1 | 9000 专用：SSO 会话、OAuth2 授权记录、令牌内省与客户端缓存 |

### 登录逻辑速查（三条入口，同一道闸）

三条路最终都汇到 9000 同一张登录表单、同一道签发准入闸（用户 RBAC 码 ∩ 客户端 scopes，无交集即拒）：

```text
① 管理台  8001 /login ──► 8085 (admin-app) ──► 9000 登录
              admin ✔ 成功 ──► 返回管理台；user ✘ 拒（9000 红条 error=access_denied）

② 门户    8000 /login ──► 8080 (portal-app) ──► 9000 登录
              user  ✔ 成功 ──► 返回已登录门户；admin ✘ 拒（9000 红条）

③ 直登 9000  http://localhost:9000/（或直接打开登录页）
              ──► 自动并入门户流（同②）：user ✔ 落已登录门户；admin ✘ 拒
              即 9000 默认归属门户；管理员唯一入口是 8001
```

三方演示（8081/8082/8083）不走「客户端 × 角色」约束——其客户端 scope 映射不到任何业务码，
令牌一律 0 业务码，业务接口（`/biz/**`、`/admin/**`）调用一律 403：权限收敛在 API 层，而非登录层。

---

## 三、模块职责

### 服务端（单服务）

| 模块 | 端口 | 库 | 职责 |
|---|---|---|---|
| iam-authorization-server | 9000 | `iam` | OAuth2/OIDC 协议运行时（授权码、密码、设备码、刷新）+ 管理 API `/admin/**` + 业务 API `/biz/**` + RBAC 角色权限 + 端点准入裁决 + 签发准入 |

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
> 控制器方法须位于 `controller.admin|biz` 包下才会被扫描入表，否则落认证档。

---

## 六、关键设计裁定

1. **fail-closed 是默认姿态**：签发、自省、端点准入三层任一环缺口即拒绝，无"猜解放行"路径。
2. **双维正交**：用户维（角色→权限码，细粒度）与客户端维（scope→权限码，粗粒度）收敛到同一张 `sys_permission` 字典后取交集，不新建第二权威。
3. **字典演进走 SQL 种子**：`sys_scope` 等只读字典不提供页面写入口，避免"页面"与"种子"双演进路径打架。
4. **已退役的旧机制**（本轮移除，勿再引用）：`iam_client_policy`（登录边界策略）、`AuthServerProperties`（客户端白名单）、`ADMIN_SERVICE_TOKEN`/`PORTAL_SERVICE_TOKEN`（粗档常量与 M2M 分支）、`sys_user.user_label`（标签列与降级猜测）。

---

## 七、文档导航

> **项目介绍**即本文档。以下 7 份为 `docs/` 的全部内容：

| 文档 | 覆盖维度 | 关键内容 |
|---|---|---|
| [概要设计](./docs/概要设计.md) | 概要设计 | 系统定位、部署拓扑、模块划分、技术选型、9 项核心决策、数据流 |
| [详细设计](./docs/详细设计.md) | 详细设计 | 3 条安全链、认证与令牌流程、Redis key、签发/端点准入实现、扫描算法、关键类索引 |
| [权限与安全设计](./docs/权限与安全设计.md) | 权限维度 | 双维交集、四层裁决链、17 权限码、3 scope、角色绑定、已退役机制 |
| [数据库设计文档](./docs/数据库设计文档.md) | 数据库设计 | 16 表结构、字典写入语义（谁能写什么）、种子数据速查、落库步骤 |
| [接口文档](./docs/接口文档.md) | 对外接口 | 协议端点 + 48 个业务接口清单、**三方接入指南**（授权码/密码/设备码/刷新/内省） |
| [编码规范](./docs/编码规范.md) | 编码规范 | **包结构硬性要求**、8 条红线、命名规范、禁止事项黑名单 |
| [操作说明](./docs/操作说明.md) | 操作运维 | 环境前置、初始化、启停（顺序约束）、冒烟、6 类排障、管理端截图（待补） |

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
2. **新端点 fail-closed 收口**：`iam_endpoint_policy` 扫描默认值由 `AUTHENTICATED` 改为 `status=0`（新端点默认拒绝），人工确认后再启用——消除「已入表但种子未配码」期间的宽松窗口（当前无页面可收紧，只能改种子）。
3. **登录防爆破**：登录端点失败限流 + 账号临时锁定（历史改造清单 A1，始终未实现）。
4. **敏感操作审计表**：记录谁、对哪个对象、改了什么、结果，覆盖用户/客户端/角色/权限/准入的写操作。
5. **密码策略**：密码历史（禁止近期复用）+ 过期策略。
6. **客户端密钥治理**：`client_secret` 明文（演示为 `123456`）与 BCrypt 哈希会经 `GET /admin/clients/{id}` 回显给调用方——建议对外掩码，密钥改由环境变量/密钥管理注入。
7. **代码卫生**：孤儿权限码 `policy:write`（无任何端点引用）、`resolveDomain` 返回值只剩判空用途（应改 `isManagedPackage()`）、`AdminUserDataController` 的 `/users/{code}/data` 已无前端调用方（级联已本地化）、`sql/iam.sql` 内 13 行注释掉的 capability 死块与 `iam_client_policy` 遗留 DROP、BFF 配置键 `iam.resource-service-base-url`（值正确指向 9000，但键名仍引用已删除的 resource-service，应改名并同步 `ApiProxyController` 的 `@Value`）。
8. **`iam_external_identity` 接通**：外部身份绑定（微信/企业微信/GitHub）仅建表、从未接通。
9. **安全基线补强**：登录 CSRF 豁免（静态登录页无 token）改为可取 token；`maximumSessions(-1)` 改有限并发；OAuth 2.1 对齐（密码 grant 仅留演示、PKCE 已全量强制）。
10. **服务自愈**：计划任务随开机自启 + 端口健康检查自动拉起（当前机器重启后三服务全灭，需手工重启）。
11. **文档配图**：6 张架构/时序图（IMG-1~6，各设计文档内已列清单）+ 9 张管理端截图（SHOT-1~9，`操作说明` §七已列）。
