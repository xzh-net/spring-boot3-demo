# iam-platform — 统一认证管理平台（单服务合并形态）

基于 Spring Authorization Server 1.4.1 的 OAuth2 / OIDC 统一认证管理平台。**平台已合并为单服务单库**：原认证中心 (`iam-authorization-server`) 与原资源中心 (`iam-resource-service`) 合并为 **9000 单服务**（包结构 `net.xzh.iam.{common,auth,resource}`），单 MySQL 库 **`iam`**（**17 表**，零租户）。

**权限模型分两层**：登录层 = `client_login_policy` 准入表裁决（谁能否登录哪个客户端，allow-list fail-closed）；授权层 = 令牌业务权限码 **用户 RBAC 码 ∩ 客户端授权范围 (scope) 展开码**，自省层 fail-closed 注入，任一维缺口即 403。两层解耦，改权限码不影响登录边界，实现**混合登录隔离**（门户 / 管理端用户不跨端登录）。

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
│   ├── iam-client-web-demo/            #   :8081  授权码 + PKCE（oa-web-app）
│   ├── iam-client-h5-demo/             #   :8084  授权码 + PKCE（oa-h5-app · OA 的 H5 形态, 手机模拟器壳）
│   └── iam-client-device-demo/         #   :8082  设备码 RFC 8628（device-app）
│
├── sql/                                # ──【数据库脚本】单库 iam──
│   ├── iam.sql                         #   合并基线（17 表 + 全部种子，新库初始化唯一入口）
│   └── migration/                      #   既有库增量升级脚本（V6.2–V6.16）
│
├── docs/                               # ──【文档】概要/详细设计 · 权限 · 库 · 接口 · 编码 · 操作（7 份）──
├── start-all.ps1 / start-all.bat       # ──【脚本】一键启停核心服务──
├── reset-init.ps1 / reset-init.bat     # ──【脚本】一键重置: 清库+清Redis+UUID种子+重启 (从头验证用)──
└── 待处理.txt
```

---

## 二、端口规划

端口段约定：`8000~8009` 前端静态站 ｜ `8080~8089` BFF 与三方演示 ｜ `9000` 服务端核心。
MySQL / Redis 在 `192.168.31.161`（库 `iam`；Redis 分库：db1=认证中心 9000 专用、db3=管理 BFF 8085 专用），改地址见
`server/iam-authorization-server/src/main/resources/application-{profile}.yml`；启动顺序见「四、快速启动」。

| 服务 | 端口 | 入口 URL | 说明 | 备注（进去以后的主要逻辑） |
|---|---|---|---|---|
| **iam-authorization-server**<br>服务端（唯一 Java 服务） | 9000 | `http://localhost:9000` | 认证中心：登录页 + OAuth2/OIDC 协议端点 + 全部业务 API | 直接访问 `/` 或登录页直登，**自动并入门户登录流**（见下方速查③）。登录表单是管理/门户两条流**共用**的，靠签发准入闸按「客户端 × 角色」裁决：portal-app 只放行 PORTAL 用户、admin-app 只放行 ADMIN 用户。`/admin/**`、`/biz/**` 的权限码裁决也在此执行，管理页对其**只读**；另有免令牌测试口 `/permitall/time` |
| **iam-admin-bff** | 8085 | `http://localhost:8085` | 管理端 BFF（OAuth2 Client: admin-app，授权码 + PKCE） | 未登录访问任意路径**自动发起登录**（无自有登录页，表单即 9000 那张），成功返回管理台。**仅管理员可进**：`client_login_policy` 准入表 admin-app 只放行 ADMIN 角色，普通用户未命中 → 9000 红条拒绝。`/admin/**` 透传 9000（Bearer 只在 BFF 服务端内存附加，token 不出后端）；`/api/current-user` 为 BFF 原生（读本地会话） |
| **iam-admin-web** | 8001 | `http://localhost:8001` | 管理后台前端（node 静态 + 代理） | 未登录访问 → `/login` → 8085 → 9000 登录 → 成功**返回管理台**。**门户用户（user）不可登录**，原因同上：`client_login_policy` 准入表 admin-app 只放行 ADMIN 角色。页面：用户/角色/权限/客户端/**登录准入**/授权管理/在线用户，外加只读「授权范围」「资源准入(51 行)」。node 将 `/admin/**` 与 `/api/**` 代理到 8085 |
| **iam-portal-bff** | 8080 | `http://localhost:8080` | 门户 BFF（OAuth2 Client: portal-app，Confidential + PKCE） | 未登录自动发起登录，成功**返回已登录门户**。**仅普通用户可进**：`client_login_policy` 准入表 portal-app 只放行 PORTAL 角色，admin 未命中 → 9000 红条拒绝。`/api/*` 为 BFF 原生（会话层）；可见应用列表由 BFF **服务端代调** 9000 `/biz/clients/mine` |
| **iam-portal-web** | 8000 | `http://localhost:8000` | 门户前端（node 静态 + 代理） | 未登录：显示新闻动态/通知公告演示数据，登录入口在导航栏右上角。`/login` → 8080 → 9000 登录 → 成功**返回已登录门户**（应用中心卡片）。**管理员（admin）不可登录**，原因同上：`client_login_policy` 准入表 portal-app 只放行 PORTAL 角色。登录后点应用卡片即 SSO 跳对接应用；node 将 `/api/*` 代理到 8080 |
| **iam-client-web-demo** | 8081 | `http://localhost:8081` | 三方演示：授权码 + PKCE（oa-web-app） | 流程演示：登录 → code 换 token → 调 API → 内省 → 刷新/登出，页面可见真实令牌。oa-web-app 准入为 **ANY**（对所有登录用户开放），但其 `third.profile` 空映射 → 令牌 **0 个业务码**；调门户接口 `/biz/clients/mine` 一律 **403** —— fail-closed 现场 |
| **iam-client-device-demo** | 8082 | `http://localhost:8082` | 三方演示：设备码（device-app） | RFC 8628 全流程：取码 → 本页 `/activate` 输入 user_code → 登录 + 同意 → 设备端轮询换票。device-app 为**公开客户端（无密钥）**，须用户同意后才发令牌 |
| **iam-client-h5-demo** | 8084 | `http://localhost:8084` | OA 演示：纯 Web 应用的 H5 形态（oa-h5-app，与 web 版同款对接） | 手机模拟器壳 + 硬编码模块（请假管理/报销审核/审批中心…），点模块即发起授权码登录（SSO 在场免登）。机密客户端 + PKCE + 服务端换票，与 8081 本质一致 |
| MySQL | 3306 | `192.168.31.161` | 库 `iam`（17 表） | 种子唯一来源 `sql/iam.sql`；字典/准入表的写入语义见「五、核心架构」 |
| Redis | 6379 | `192.168.31.161` | **db1**=9000 专用：SSO 会话、OAuth2 授权记录、令牌内省与客户端缓存；**db3**=8085 专用：管理 BFF 会话与令牌（分库物理隔离，键前缀 oauth2:* / admin-bff:* 双保险） |

### 登录逻辑速查（三条入口，同一道闸）

三条路最终都汇到 9000 同一张登录表单、同一道签发准入闸（查 `client_login_policy` 准入表，allow-list 未命中即拒）：

```text
① 管理台  8001 /login ──► 8085 (admin-app) ──► 9000 登录
              admin ✔ 成功 ──► 返回管理台；user ✘ 拒（9000 红条 error=access_denied）

② 门户    8000 /login ──► 8080 (portal-app) ──► 9000 登录
              user  ✔ 成功 ──► 返回已登录门户；admin ✘ 拒（9000 红条）

③ 直登 9000  http://localhost:9000/（或直接打开登录页）
              ──► 自动并入门户流（同②）：user ✔ 落已登录门户；admin ✘ 拒
              即 9000 默认归属门户；管理员唯一入口是 8001
```

三方演示（8081/8082/8084）的登录资格同样由准入表裁决（`oa-web-app`/`mobile-app`=ANY 对所有登录用户开放、`device-app`=仅 THIRD_PARTY 角色）；其令牌业务码一律为 0（scope 映射不到业务码），业务接口（`/biz/**`、`/admin/**`）调用一律 403：权限收敛在 API 层，而非登录层。

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
| iam-admin-web | 8001 | 管理后台静态站（八项菜单；授权范围字典与登录准入已并入「客户端管理」，只读「资源准入」页保留） |
| iam-portal-web | 8000 | 门户静态站（客户端列表与 SSO 跳转卡片） |
| iam-client-*-demo | 8081/8082/8084 | 三种 OAuth2 接入姿势演示（授权码 / 设备码 / OA H5 形态） |

---

## 四、快速启动

### 1. 初始化数据库（单库 `iam`）

依赖 MySQL 8 + Redis。导入合并基线（17 表，零租户）：

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam DEFAULT CHARSET utf8mb4"
mysql -u root -p iam < sql/iam.sql
# 既有库升级用 sql/migration/（V6.2–V6.16），新库无需执行
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
cd client/iam-client-h5-demo     && node server.js   # :8084
```

### 4. 默认账号

| 账号 | 密码 | 角色 | 用途 |
|---|---|---|---|
| `admin` | `123456` | `ADMIN`（持 16 个管理域权限码） | 管理后台 |
| `user` | `123456` | `PORTAL`（持 1 个门户权限码） | 门户 / 演示项目 |
| `zhangsan` | `123456` | `THIRD_PARTY`（0 权限码） | 设备码流程验证（`device-app` 准入仅此角色） |

### 5. 默认客户端

| client_id | 授权模式 | 持有 scope | 适用 |
|---|---|---|---|
| `admin-app` | 授权码 + 刷新 | `admin.full`（16 码） | 管理后台 BFF |
| `portal-app` | 授权码 + 刷新（PKCE） | `portal.profile`（1 码） | 门户 BFF |
| `oa-web-app` | 授权码 | `third.profile`（空映射） | 传统 Web 应用演示 |
| `device-app` | 设备码 | 无业务 scope | 电视 / IoT / CLI |
| `mobile-app` | 授权码 + PKCE | 无业务 scope | 原生 App / SPA |

---

## 五、核心架构：双维权限控制

### 裁决链（四层，全部 fail-closed）

```text
① 签发准入  /oauth2/authorize        client_login_policy 准入表未命中 → 拒发码 → 登录页越权提示
② 令牌自省  RbacAuthorities...        用户码 ∩ 客户端scope码 = 注入的业务权限码
③ 端点准入  iam_endpoint_policy       请求(方法+路径) → 所需权限码 ∈ 令牌码 才放行
④ 域白名单  已退役                    客户端维度隔离由 ①② 的 scope 交集承担
```

### 数据模型（17 表，按职责分组）

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

1. **fail-closed 是默认姿态**：签发（准入表无配置即拒）、自省、端点准入三层任一环缺口即拒绝，无"猜解放行"路径。
2. **两层解耦**（2026-11-04 裁定）：**登录层** = `client_login_policy` 准入表（client × 主体 allow-list，页面可维护），**授权层** = 用户维（角色→权限码）与客户端维（scope→权限码）收敛到同一张 `sys_permission` 字典后取交集。两层各司其职、互不影响——改权限码不动登录边界，改准入表不动令牌业务码。
3. **字典演进走 SQL 种子**：`sys_scope` 等只读字典不提供页面写入口，避免"页面"与"种子"双演进路径打架。
4. **已退役的旧机制**（本轮移除，勿再引用）：`iam_client_policy`（登录边界策略）、`AuthServerProperties`（客户端白名单）、`ADMIN_SERVICE_TOKEN`/`PORTAL_SERVICE_TOKEN`（粗档常量与 M2M 分支）、`sys_user.user_label`（标签列与降级猜测）。
5. **新端点由启动自扫描自动入库**（2026-11-02 裁定）：`iam_endpoint_policy` 无页面写入口，扫描发现新端点即以 `AUTHENTICATED` 宽松档补行（不剪除、不回写），精确权限码由种子提供。**配套操作纪律：新增端点后必须先补种子（`sql/iam.sql`）再开放调用**——种子未配码期间该端点为「持有效令牌即可」的宽松窗口；如未来出现实际安全事件可重议 `status=0` 默认拒绝方案。

---

## 七、文档导航

> **项目介绍**即本文档。以下 7 份为 `docs/` 的全部内容：

| 文档 | 覆盖维度 | 关键内容 |
|---|---|---|
| [概要设计](./docs/概要设计.md) | 概要设计 | 系统定位、部署拓扑、模块划分、技术选型、9 项核心决策、数据流 |
| [详细设计](./docs/详细设计.md) | 详细设计 | 3 条安全链、认证与令牌流程、Redis key、签发/端点准入实现、扫描算法、关键类索引 |
| [权限与安全设计](./docs/权限与安全设计.md) | 权限维度 | 双维交集、四层裁决链、17 权限码、3 scope、角色绑定、已退役机制 |
| [数据库设计文档](./docs/数据库设计文档.md) | 数据库设计 | 17 表结构、字典写入语义（谁能写什么）、种子数据速查、落库步骤 |
| [接口文档](./docs/接口文档.md) | 对外接口 | 协议端点 + 51 个业务接口清单、**三方接入指南**（授权码/设备码/刷新/内省） |
| [编码规范](./docs/编码规范.md) | 编码规范 | **包结构硬性要求**、8 条红线、命名规范、禁止事项黑名单 |
| [操作说明](./docs/操作说明.md) | 操作运维 | 环境前置、初始化、启停（顺序约束）、冒烟、6 类排障、管理端截图（待补） |

---

## 八、更新日志

| 日期 | 类型 | 内容 |
|---|---|---|
| 2026-11-17 | 调整 | **C-1 客户端治理聚合落地**：删除菜单与页面「登录准入」「授权范围」（`login_policy.html` / `scope.html`），登录准入配置与 scope 字典明细并入「客户端管理」编辑弹窗（列表新增「登录准入」列，治理分区独立保存，治理概览只读体检标红），资源准入页补「所属授权范围组」反查；**菜单/页面 = 前端静态文件，表、种子、写接口零变化，无需重刷数据库（iam.sql 不动、V6.x 不涉及）** |
| 2026-11-04 | 增加 | **设备码签发准入闸**：`DeviceCodeGrantAuthenticationProvider` 用户激活确认后调 `LoginAdmissionService.canLogin`，未命中 `access_denied` —— 设备码不经 `/oauth2/authorize`，此前 `client_login_policy` 对其不生效（README 待办 P1-3 活路径半边） |
| 2026-11-04 | 删除 | **密码模式三件套**（`PasswordGrantAuthenticationConverter`/`Provider`/`Token`）及 `AuthorizationServerConfig` 装配、`passwordEncoder` 参数、`test.http` 示例；OAuth 2.1 废弃该授权类型且无客户端注册（P1-3 另半边） |
| 2026-11-04 | 增加 | **登录准入模块**：`client_login_policy` 表（client × 主体 allow-list）+ `LoginAdmissionService` + `AdminLoginPolicyController` + 管理页 `login_policy.html`（菜单「登录准入」）；签发准入由「权限码交集」改为「准入表裁决」，登录/授权两层解耦，`IssuanceAdmissionService` 删除 |
| 2026-11-04 | 修改 | 种子 `device-app` 登录准入收敛为仅 `THIRD_PARTY` 角色（原对所有登录用户开放）；新增种子用户 `zhangsan`（THIRD_PARTY，0 权限码）用于设备码流程验证 |
| 2026-11-04 | 增加 | README §九 待办新增 A 组「架构设计问题」（P0-1 令牌 scope claim 失真 / P0-2 表驱动端点准入两头不占 等 7 项） |
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

### A. 架构设计问题（2026-11-04 双维权限架构评审，按优先级）

> 优先级：**P0** = 对外契约失真 / 已具备可修条件，应优先处理；**P1** = 语义缺口，特定条件下爆发；**P2** = 韧性与代码卫生。

- **P0-1 令牌 `scope` claim 与实际授权脱钩（对外契约失真）**：自省裁决只取 `client_id` 查注册表（`RbacAuthoritiesOpaqueTokenIntrospector` L72-73 → `ScopeService.resolveClientBusinessCodes` 读 `oauth2_registered_client.scopes`），**从不读同一批 attributes 里的 `scope`**；但 `RedisOpaqueTokenIntrospector` L110/L118 却把 `authorizedScopes` 写进 claim，`EnrichedOAuth2TokenIntrospectionAuthenticationProvider` L132-135 还「无条件补齐」给外部消费方。后果：① RFC 7662 `/oauth2/introspect` 返回的 `scope` 与平台实际放行的业务码不一致——**实证**：`iam-admin-bff` 申请 `openid,profile,read,write`（无 `admin.full`），令牌 claim 无管理权限却实际注入 16 个管理码；② 标准 OAuth2「按令牌收窄 scope」能力在业务码维度失效；③ 外部资源方按 RFC 语义实现会得出与平台相反的结论。安全底线未破（业务码 ⊆ 注册 scope 展开上限，请求侧无法提权）。**建议方向**：内省响应回传实际生效业务码（自定义 `permissions` claim），或明文声明 `scope` claim 不参与裁决、外部方不得依赖。

- **P0-2 表驱动端点准入「两头不占」**：付出无参照完整性代价——`iam_endpoint_policy.required_authority` 按字符串引用权限码，`RbacService.updatePermission()` **无引用守卫**（仅 `deletePermission()` 有），页面又允许改名 → 改名后引用行静默失联、端点永久 403；同时**未拿到运行时可改的收益**（页面只读 + 启动扫描不回写）。**建议方向二选一**：① 改 `@PreAuthorize` 编译期声明，种子表降级为审计/文档；② 保留表驱动，则补引用完整性（禁止改名或级联更新）并提供页面写入口。

- ~~**P1-1 签发准入与自省层对「空 scope」语义不一致**~~ **已解决（2026-11-04）**：`IssuanceAdmissionService` 及其逃逸阀已删除，签发准入改查 `client_login_policy` 准入表（allow-list，无配置即拒）；登录层不再读 scope，两层语义分家问题消失。

- **P1-2 consent 不参与裁决**：`oauth2_authorization_consent` 仅作审计记录 + 撤销时踢会话，`RbacAuthoritiesOpaqueTokenIntrospector` 完全不读它。第一方场景无害；接入**需用户自主授权的第三方应用**时是真实缺口（届时 consent 须升为第三裁决维度）。

- ~~**P1-3 `password` / `device_code` 不走签发准入闸**~~ **已解决（2026-11-04）**：① `password` 三件套已删除（OAuth 2.1 废弃该授权类型且无客户端注册）；② `device_code` 已在 `DeviceCodeGrantAuthenticationProvider` 用户激活确认后接入 `LoginAdmissionService.canLogin`，未命中即 `access_denied`。注：原文「无既存 scope 时全量下发客户端 scope」属**授权层**行为（下发的是 scope 而非业务码），业务码仍由自省层交集 fail-closed 兜底，不在本条范围。

- **P2-1 端点宽松窗口的隐性 fail-open**：新端点自扫描补 `AUTHENTICATED`、种子配码前为「持令牌即可」——此部分**已裁定关闭**（见下方第 2 条与 §六.5，不重开）；但 `EndpointPolicyScanInitializer` L38-40 **吞异常** → 表加载失败时快照为空，**全部端点退化为认证档**，该点未被既有裁定覆盖，需单独补（加载失败应拒绝启动或告警）。

- **P2-2 `authorizedScopes` 断头数据**：授权记录的 `authorizedScopes` 被 `RedisOpaqueTokenIntrospector` L110 读出后，唯一去处是 L118 `attributes.put("scope")`，全 `server/` 无任何 `attributes.get("scope")` 消费者（grep 0 命中）。与 P0-1 同源，修 P0-1 时一并清理。

### B. 既有待办

1. **YAML 配置分类**：整理当前项目存在的硬编码，按 `application-auth.yaml` / `application-resource.yaml` 的格式，拆分到不同的配置文件中。
2. ~~新端点 fail-closed 收口~~ **已裁定关闭（2026-11-02）**：维持「启动自扫描自动添加（`AUTHENTICATED` 宽松档）+ 种子配精确权限码」的现行模式，不改为 `status=0`。新端点的宽松窗口由操作纪律兜底：**新增端点后先补种子再开放调用**（见「六、关键设计裁定」第 5 条）。
3. **登录防爆破**：登录端点失败限流 + 账号临时锁定（历史改造清单 A1，始终未实现）。
4. **敏感操作审计表**：记录谁、对哪个对象、改了什么、结果，覆盖用户/客户端/角色/权限/准入的写操作。**与 C-1 聚合写（Phase 2）绑定排期**：客户端治理「一处配齐」的跨表写落地前，本条操作级审计必须先落地（铁律3），否则 = 把无审计的多表写收进一个按钮。
5. **密码策略**：密码历史（禁止近期复用）+ 过期策略。
6. **客户端密钥治理**：`client_secret` 明文（演示为 `123456`）与 BCrypt 哈希会经 `GET /admin/clients/{id}` 回显给调用方——建议对外掩码，密钥改由环境变量/密钥管理注入。
7. **代码卫生**：孤儿权限码 `policy:write`（无任何端点引用）、`resolveDomain` 返回值只剩判空用途（应改 `isManagedPackage()`）、`AdminUserDataController` 的 `/users/{code}/data` 已无前端调用方（级联已本地化）、`sql/iam.sql` 内 13 行注释掉的 capability 死块与 `iam_client_policy` 遗留 DROP、BFF 配置键 `iam.resource-service-base-url`（值正确指向 9000，但键名仍引用已删除的 resource-service，应改名并同步 `ApiProxyController` 的 `@Value`）。
8. **`iam_external_identity` 接通**：外部身份绑定（微信/企业微信/GitHub）仅建表、从未接通。
9. **安全基线补强**：登录 CSRF 豁免（静态登录页无 token）改为可取 token；`maximumSessions(-1)` 改有限并发。~~OAuth 2.1 对齐（密码 grant 仅留演示、PKCE 已全量强制）~~ **密码 grant 已删除（2026-11-04）、PKCE 已全量强制**，本条余 CSRF 与并发两项。
10. **服务自愈**：计划任务随开机自启 + 端口健康检查自动拉起（当前机器重启后三服务全灭，需手工重启）。
11. **文档配图**：6 张架构/时序图（IMG-1~6，各设计文档内已列清单）+ 9 张管理端截图（SHOT-1~9，`操作说明` §七已列）。
12. **用户模块编码字段治理**：现状杂乱，三件事——① `user_code` 格式不统一：存量为 `u_`+32hex 与裸 `zhang3` 混杂，**格式已裁定为标准 UUID（`550e8400-e29b-41d4-a716-446655440000`）**，新建用户已改为系统自动生成、页面只读不可编辑、服务端格式校验（2026-11-03）；存量回填可由 `reset-init.bat` 一键完成（清库重载 UUID 种子 + 清 Redis 会话/令牌，2026-11-03）；② 历史命名双职遗留：`username` 曾装 user_code、`principalName` 至今兼任 API 参数，展示字段与 API 取值须持续分离（在线/授权两页已拆，后续新接口注意）；③ 关联键选型已裁定（2026-11-03）：维持字符串，物理主键用自增/雪花 id、对外关联键用 user_code，不做类型变更。

### C. 展示与聚合收口（2026-11-17 补录）

1. ~~**客户端治理聚合呈现**~~ **已落地（2026-11-17）**：登录准入 / 授权范围 / 资源准入 三处配置分散三页 → 按拍板方案收敛为「客户端管理 = 客户端治理唯一入口」：① 删除菜单与页面 `login_policy.html`、`scope.html`（菜单 10→8 项）；② scope 字典明细下沉至编辑弹窗只读区（组→码映射 + 引用客户端，仍走 iam.sql 种子）；③ 登录准入迁入编辑弹窗「登录准入」分区（**分区独立保存**，复用原 `PUT /admin/login-policies/{clientId}`），列表页新增「登录准入」列；④ 治理概览只读体检（准入行 / 展开码 / 端点覆盖 + 标红）；⑤ 资源准入页补「← 所属授权范围组」反查（未入组码标橙=孤儿码风险）。
   **三条铁律（约束后续 Phase 2 聚合写）**：铁律1 汇聚视图与入口、**不汇聚事务**（各分区独立提交）；铁律2 字典永远只读（iam.sql = git 审计链）；铁律3 聚合写必须先落 B-4（操作级审计）与 P0-2（引用完整性），顺序不可反。
   **数据/种子影响裁定（本次实证）**：菜单与页面为前端静态文件，不入库 → `client_login_policy`/`sys_scope`/`sys_scope_permission`/`iam_endpoint_policy` 表、`iam.sql` 种子、V6.15/V6.16 迁移、全部管理 API **均零变化**（新列与概览仅用既有只读接口），**准入/资源表无需重刷、无需 reset-init**；文档健康检查与截图清单已同步（操作说明 §四/§七、接口文档、详细设计、数据库设计、权限与安全设计）。
2. **consent 展示层收口**：四点并存——① `ConsentController` 将 `clientName` 误传为 `clientId`，页面大标题与 ID 行重复显示技术标识，注册名（如「管理后台」）从未出现；② `describeScope` 仅 5 词硬编码，`admin.full`/`portal.profile`/`third.profile` 走 default 分支原样回显（desc 还把 key 重复一遍），`read`/`write` 译为「读取权限/写入权限」无资源指向；③ 页头「应用请求访问您的部分信息」与实际授予的 API 操作权限不符——业务码封顶结果（admin.full→16 码、third.profile→空）对用户完全不可见；④ scope 勾选框为装饰（div 绘制、hidden input 无条件提交），呈现可部分勾选实为全有全无。与 P0-1 同源但层级不同：P0-1 是协议 claim 契约（对外），本条是人话页面（对用户）。
3. **（触发式）三方域首个业务端点开通**：`third.profile` 当前「准入 ANY + 字典空映射」是**留白而非缺陷**（iam.sql 种子备注与授权范围页已记录：三方域暂无端点、空展开 fail-closed、仅 OIDC 标准能力）。但触发点无条目挂靠——三方域开第一个业务端点时，必须先补 `sys_scope_permission` 映射并配资源端点准入，否则该端所有业务接口恒 403。
