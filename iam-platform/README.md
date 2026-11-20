# iam-platform — 统一认证管理平台

基于 Spring Authorization Server 的 OAuth2 / OIDC 统一认证管理平台。**单服务单库**形态：认证中心与资源中心合并为 **9000 单服务**（包 `net.xzh.iam.{common,auth,resource}`），单 MySQL 库 **`iam`**（**18 表**，零租户）。

**权限模型分两层**：登录层 = `client_login_policy` 准入表裁决（谁能否登录哪个客户端，allow-list，未配置即拒绝）；授权层 = 令牌业务权限码 **用户 RBAC 码 ∩ 客户端授权范围 (scope) 展开码**，自省层注入，任一维缺口即 403。两层解耦，改权限码不影响登录边界，实现混合登录隔离（门户 / 管理端用户不跨端登录）。

---

## 一、目录结构

```text
iam-platform/
├── README.md                           # 本文件
├── docs/                               # 设计文档（8 份）
│   ├── 概要设计.md
│   ├── 详细设计.md
│   ├── 权限与安全设计.md
│   ├── 数据库设计文档.md
│   ├── 接口文档.md
│   ├── 编码规范.md
│   ├── 操作说明.md
│   └── CHANGELOG.md                    # 变更日志（开发者复盘用）
├── server/
│   └── iam-authorization-server/       # :9000 单服务（协议端点 + 业务 API）
├── bff/
│   ├── iam-admin-bff/                  # :8085 管理后台 BFF
│   └── iam-portal-bff/                 # :8080 门户 BFF
├── web/
│   ├── iam-admin-web/                  # :8001 管理后台静态站
│   └── iam-portal-web/                 # :8000 门户静态站
├── client/
│   ├── iam-client-web-demo/            # :8081 授权码 + PKCE 演示
│   ├── iam-client-h5-demo/             # :8084 OA H5 形态演示
│   └── iam-client-device-demo/         # :8082 设备码 RFC 8628 演示
├── sql/
│   ├── iam.sql                         # 合并基线（新库初始化唯一入口）
│   └── migration/                      # 既有库增量升级脚本
├── start-all.ps1 / start-all.bat       # 一键启停
└── reset-init.ps1 / reset-init.bat     # 一键重置（清库+清Redis+重启）
```

---

## 二、端口规划

端口段约定：`8000~8009` 前端静态站 ｜ `8080~8089` BFF 与三方演示 ｜ `9000` 服务端核心。

| 服务 | 端口 | 入口 URL | 说明 |
|---|---|---|---|
| iam-authorization-server | 9000 | `http://localhost:9000` | 认证中心：登录页 + OAuth2/OIDC 协议端点 + 全部业务 API |
| iam-admin-bff | 8085 | `http://localhost:8085` | 管理端 BFF（admin-app，授权码 + PKCE） |
| iam-admin-web | 8001 | `http://localhost:8001` | 管理后台前端（用户/角色/权限/客户端/资源准入/授权管理/在线用户） |
| iam-portal-bff | 8080 | `http://localhost:8080` | 门户 BFF（portal-app，Confidential + PKCE） |
| iam-portal-web | 8000 | `http://localhost:8000` | 门户前端（客户端 SSO 卡片） |
| iam-client-web-demo | 8081 | `http://localhost:8081` | 三方演示：授权码 + PKCE（oa-web-app） |
| iam-client-device-demo | 8082 | `http://localhost:8082` | 三方演示：设备码（device-app） |
| iam-client-h5-demo | 8084 | `http://localhost:8084` | OA 演示：纯 Web 应用的 H5 形态 |

MySQL / Redis 地址与密码见 `server/iam-authorization-server/src/main/resources/application-{profile}.yml`；启动顺序见「四、快速启动」。

### 登录逻辑速查

三条路最终都汇到 9000 同一张登录表单、同一道签发准入闸（查 `client_login_policy` 准入表，allow-list 未命中即拒）：

```text
① 管理台  8001 /login ──► 8085 (admin-app) ──► 9000 登录
              admin ✔ 成功 ──► 返回管理台；user ✘ 拒

② 门户    8000 /login ──► 8080 (portal-app) ──► 9000 登录
              user  ✔ 成功 ──► 返回已登录门户；admin ✘ 拒

③ 直登 9000  http://localhost:9000/
              ──► 自动并入门户流：user ✔ 落已登录门户；admin ✘ 拒
              即 9000 默认归属门户；管理员唯一入口是 8001
```

三方演示（8081/8082/8084）的登录资格同样由准入表裁决；其令牌业务码一律为 0（scope 映射不到业务码），业务接口调用一律 403——权限收敛在 API 层，而非登录层。

---

## 三、模块职责

### 服务端

| 模块 | 端口 | 职责 |
|---|---|---|
| iam-authorization-server | 9000 | OAuth2/OIDC 协议运行时（授权码、设备码、刷新）+ 管理 API `/admin/**` + 业务 API `/biz/**` + RBAC 角色权限 + 端点准入裁决 + 签发准入 |

### 体验面 / 前端 / 客户端示例

| 模块 | 端口 | 职责 |
|---|---|---|
| iam-admin-bff | 8085 | 管理 BFF：OAuth2 Client(admin-app) 授权码 SSO 登录，Bearer 透传管理 API |
| iam-portal-bff | 8080 | 门户 BFF：OAuth2 Client(portal-app) Confidential + PKCE，独立会话与 RP-Initiated 登出 |
| iam-admin-web | 8001 | 管理后台静态站（八项菜单） |
| iam-portal-web | 8000 | 门户静态站（客户端列表与 SSO 跳转卡片） |
| iam-client-*-demo | 8081/8082/8084 | 三种 OAuth2 接入姿势演示 |

---

## 四、快速启动

### 1. 初始化数据库（单库 `iam`）

依赖 MySQL 8 + Redis。导入合并基线（18 表，零租户）：

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS iam DEFAULT CHARSET utf8mb4"
mysql -u root -p iam < sql/iam.sql
# 既有库升级用 sql/migration/，新库无需执行
```

### 2. 启动核心服务（顺序固定）

```bash
cd server/iam-authorization-server && mvn spring-boot:run     # :9000  必须最先起
cd bff/iam-admin-bff        && mvn spring-boot:run     # :8085  依赖 9000（启动时拉 OIDC discovery）
cd web/iam-admin-web        && node server.js          # :8001  管理后台前端
```

> **启动顺序**：必须先 9000 后 8085 —— BFF 启动时要拉 `/.well-known/openid-configuration`，9000 未就绪会直接退出。
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
| `zhangsan` | `123456` | `THIRD_PARTY`（0 权限码） | 设备码流程验证 |

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

### 裁决链（四层，全部未配置即拒绝）

```text
① 签发准入  /oauth2/authorize         client_login_policy 准入表未命中 → 拒发码 → 登录页越权提示
② 令牌自省  RbacAuthorities...         用户码 ∩ 客户端scope码 = 注入的业务权限码
③ 端点准入  iam_endpoint + iam_endpoint_permission
                                    请求(方法+路径) → 所需权限码 ∈ 令牌码 才放行
④ 域白名单  已删除                     客户端维度隔离由 ①② 的 scope 交集承担
```

### 数据模型（18 表）

| 分组 | 表 |
|---|---|
| 协议数据 | `oauth2_registered_client` / `oauth2_authorization_record` / `oauth2_authorization_consent` |
| 身份与凭据 | `sys_user` / `iam_external_identity` |
| RBAC（用户维） | `sys_role` / `sys_user_role` / `sys_permission` / `sys_role_permission` |
| 授权范围（客户端维） | `sys_scope` / `sys_scope_permission` |
| 端点准入 | `iam_endpoint` / `iam_endpoint_permission` |
| 平台资产 | `iam_application` / `iam_application_channel` / `iam_org` / `iam_app_authorization` |

### 字典与准入的写入语义

| 对象 | 谁能写 | 说明 |
|---|---|---|
| `sys_scope` | 仅 SQL 种子 | 组定义（三域）走种子，架构级契约 |
| `sys_scope_permission` | 种子初始化 + 权限管理页维护 | 组→码映射是配置级，页面可增删 |
| `iam_endpoint` / `iam_endpoint_permission` | 种子初始化 + 资源准入页维护 | 保存即时生效；未配行的端点走表外认证档 |
| `oauth2_registered_client.scopes` | 客户端管理页 | 标准 Spring 列作客户端↔scope 连接表 |

> **新增一个受管控接口**：`sys_permission` 加码（若有新码）并绑角色/scope → **资源准入页新增准入行**（保存即时生效，无需重启）；未配行的端点启动日志会打**漂移告警**提示补齐（仅提示、不拦截）。

---

## 六、当前生效的设计裁定

1. **未配置即拒绝是默认姿态**：签发（准入表无配置即拒）、自省、端点准入三层任一环缺口即拒绝，无"猜解放行"路径。
2. **两层解耦**：**登录层** = `client_login_policy` 准入表（client × 主体 allow-list），**授权层** = 用户维（角色→权限码）与客户端维（scope→权限码）收敛到同一张 `sys_permission` 字典后取交集。改权限码不动登录边界，改准入表不动令牌业务码。
3. **字典演进**：`sys_scope` 组定义走 SQL 种子；**配置级映射已放开**——`sys_scope_permission` 与 `iam_endpoint` 均为种子初始化 + 页面维护、保存即时生效。上线后以库数据为准。
4. **端点准入运行时模型**：
   - **每请求直查 DB**：不物化内存快照——令牌侧与端点侧都是"现算"，改权限码零窗口；多实例天然同步
   - **每请求未配置即拒绝**：准入查询/权限解析异常一律拒绝
   - **拆表 1:N 权限组合**：资源行（方法+路径+档位+组合语义）与绑定表（端点↔权限码）分离，`permission_logic` 裁决 **ALL=同时具备 / ANY=任一即可**
   - **结构性引用保留**：绑定表 `permission_id` + FK RESTRICT（被绑权限禁删）、`policy_type` 档位显式、`service_key` 服务命名空间
   - **种子定位**：一次性初始化工具，上线后以库数据为准
5. **发行者与签名密钥外置配置**：
   - `iam.issuer`（`IAM_ISSUER`）：`AuthorizationServerSettings`、`JwtDecoder` 校验器、内省 `iss` 三处同源，对外部署必须覆盖
   - `iam.jwk.keystore-path`（`IAM_JWK_KEYSTORE`）：`PersistentJwkStore` 首次启动生成并落盘、后续复用；多实例需共享同一密钥库文件；文件损坏即启动失败，不静默轮换

---

## 七、文档导航

| 文档 | 覆盖维度 |
|---|---|
| [概要设计](./docs/概要设计.md) | 系统定位、部署拓扑、模块划分、技术选型、核心决策 |
| [详细设计](./docs/详细设计.md) | 安全链、认证与令牌流程、Redis key、签发/端点准入实现 |
| [权限与安全设计](./docs/权限与安全设计.md) | 双维交集、四层裁决链、权限码字典、角色绑定 |
| [数据库设计文档](./docs/数据库设计文档.md) | 18 表结构、字典写入语义、种子数据速查 |
| [接口文档](./docs/接口文档.md) | 协议端点 + 业务接口清单、三方接入指南 |
| [编码规范](./docs/编码规范.md) | 包结构硬性要求、命名规范、禁止事项黑名单 |
| [操作说明](./docs/操作说明.md) | 环境前置、初始化、启停、冒烟、排障 |
| [CHANGELOG](./docs/CHANGELOG.md) | 变更日志（开发者复盘用，非面向终端用户） |

---

## 八、待办清单

> 按代码审计实证结果重排。**架构设计缺陷优先级最高**，业务能力为次。
> 详细变更历史见 [CHANGELOG](./docs/CHANGELOG.md)。

---

### A. 架构设计缺陷（按优先级）

#### 🔴 P0 — 生产阻塞 / 对外契约破坏

| # | 问题 | 现状 | 位置 | 影响 |
|---|---|---|---|---|
| A-P0-3 | **OIDC Client Registration 端点 permitAll** | `oidcClientRegistrationEndpoint("/oauth2/connect/register")` + permitAll | `AuthorizationServerConfig.java` | 任何人 POST 即可向系统注册新 OAuth2 客户端，无任何认证保护。与平台"allow-list 未配置即拒绝"设计哲学完全相悖 |
| A-P0-4 | **表外端点自动降级认证档 → 隐式权限提升** | `EndpointAdmissionManager` 查询准入行返回 null 时，降级为"只要有有效令牌即可" | `EndpointAdmissionManager.java` | 开发者忘记给新端点配准入行 → 端点自动变成"只需认证"而无需特定权限码 → 静默权限上抬。这是 fail-open 而非 fail-closed，上线后会出现"新加的写接口不知为啥谁都能调" |

#### 🟠 P1 — 严重但不阻塞核心流程

| # | 问题 | 现状 | 位置 | 影响 |
|---|---|---|---|---|
| A-P1-1 | **client_credentials 接口层未禁** | 虽然种子里没有 client_credentials 客户端，但 `OAuth2ClientCredentialsAuthenticationConverter` 仍在 config 中注册，SAS 默认 provider 未移除 | `AuthorizationServerConfig.java` | 如果有人通过管理端新增一个 client_credentials grant type 的客户端，整条 M2M 令牌链路就通了。当前自省层对 client_id 主体处理是偶然 fail-closed，不是显式接口层拦截 |
| A-P1-2 | **登录防爆破完全未实现** | 登录端点无失败计数、无账号临时锁定机制 | 登录表单流程 | 账号暴力破解无防线 |
| A-P1-3 | **敏感操作审计完全未实现** | 所有 Admin Controller 的写操作（用户/客户端/角色/权限/准入的增删改）裸写无审计记录 | 全栈 | 与 P0-4 "改权限码零窗口" 特性结合 = **无审计的即时生效变更** |
| A-P1-4 | **maximumSessions(-1) 无限并发** | Spring Security 会话并发限制设为 -1（不限制），SSO 会话可无限创建 | `AuthorizationServerConfig.java` | 账号被盗用可无限会话 |
| A-P1-5 | **Redis / MySQL 密码硬编码无环境变量** | `application-local.yml` 中数据库地址 `192.168.31.161:3306`、密码 `123456` 硬编码，无 `${DB_HOST}` / `${DB_PASSWORD}` 占位符 | `application-local.yml` | 生产部署必须手动改配置文件，易出错且不利于容器化 |
| A-P1-6 | **ALLOWED_REDIRECT_HOSTS 白名单硬编码 localhost 端口** | 只覆盖 localhost/127.0.0.1 的固定端口列表 | `AuthorizationServerConfig.java` | 非 localhost 或端口不在列表的 redirect_uri 全部被拒。为演示方便写死、上线必炸 |

#### 🟡 P2 — 架构质量 / 扩展性

| # | 问题 | 现状 | 位置 |
|---|---|---|---|
| A-P2-1 | **每请求直查 DB 无缓存** | 准入路径：1 查 `iam_endpoint` 全量过滤 → N 查绑定表 → 1 查权限表。`EndpointPolicyService.findRule()` 每次 `selectList` 全量加载再 Java 层 pathMatcher | `EndpointPolicyService.java` | 入口是 Spring Security 的 AuthorizationManager.check()，每个请求必调。56 行数据当前没问题，但无按 path 建索引、无 per-path 级别缓存 |
| A-P2-2 | **ApiProxyController resolveBase() 死逻辑** | 单服务合并后两个 baseUrl 都指向 `http://localhost:9000`，if/else 分流无任何意义 | `ApiProxyController.java` | 代码残留，易误导后续维护者 |
| A-P2-3 | **resource-service-base-url 配置键名残留** | admin-bff 的 application.yml 中仍存在 `iam.resource-service-base-url` 键名，值虽正确指向 9000，但键名引用已删除的 resource-service | `admin-bff/application.yml` | 代码卫生，改名并同步 `ApiProxyController` 的 `@Value` 注解 |
| A-P2-4 | **两层 introspector 双重 authorities 注入** | `RedisOpaqueTokenIntrospector` → `resolveAuthorities()` 注入 UserDetails authorities；`RbacAuthoritiesOpaqueTokenIntrospector` → 在此基础上**追加** RBAC 角色码 + scope 交集业务码。两层都改 authorities | 两个 Introspector | authorities 是合并副本，容易导致 authority 重复注入或逻辑混乱。推荐收敛到单一 Introspector |
| A-P2-5 | **密码策略缺失** | 无密码历史检查（禁止近期复用）、无过期策略 | 用户模块 | 账号长期安全性无保障 |
| A-P2-6 | **客户端密钥回显给调用方** | `GET /admin/clients/{id}` 接口回显 client_secret 明文 + BCrypt 哈希给前端 | AdminClientApiController | 应对外掩码，密钥改由环境变量/密钥管理注入 |

---

### B. 业务能力缺口

| # | 能力 | 现状 | 影响 |
|---|---|---|---|
| B-1 | **MFA / 2FA 多因素认证** | 只有用户名密码一种登录方式；`maximumSessions(-1)` 已列 P1-4 | 账号被盗用无第二道防线 |
| B-2 | **第三方身份源集成** | `iam_external_identity` 表存在但零 Controller / Service / 绑定流程接通 | 无法对接企业微信 / 钉钉 / GitHub 等外部身份源 |
| B-3 | **组织架构** | `iam_org` 表存在，但 `sys_user` 无 org_id 关联字段，无组织树管理 | 无法按组织做权限隔离 |
| B-4 | **用户自助管理** | 无忘记密码、自助改密、账号激活/停用界面，全是管理端操作 | 用户无法自助处理账号问题，运维负担重 |
| B-5 | **应用授权管理** | `iam_app_authorization` 表存在，无对应管理端页面 | 应用授权关系只能 SQL 直改 |
| B-6 | **审批流** | 新增客户端、改准入、改权限全是 admin 裸写，无审批机制 | 高危变更无审批，直接生效 |
| B-7 | **门户通知 / 新闻** | 门户首页"新闻动态"全是演示硬编码数据 | 演示功能，生产不可用 |
| B-8 | **服务自愈** | 当前机器重启后三服务全灭，需手工重启 | 无自启 + 健康检查自动拉起 |
| B-9 | **CSRF 豁免** | `AuthorizationServerConfig` 仍对 `/login` POST 和 `/oauth2/device/verify` 豁免 CSRF | 登录表单无 CSRF token，存在潜在风险 |

---

### ✅ 已验证解决（代码实证，上一轮审计确认）

| # | 问题 | 修复内容 |
|---|---|---|
| ✅1 | scope claim 与实际授权脱钩 | `scope` claim 改读注册表 `oauth2_registered_client.scopes`，与业务码授予同源 |
| ✅2 | 端点准入两头不占 | 地基=`permission_id`+FK RESTRICT；运行时=每请求直查 DB；配置通道=页面维护保存即生效 |
| ✅3 | 签发准入与自省层空 scope 语义不一致 | 签发准入改查 `client_login_policy`，登录层不再读 scope |
| ✅4 | password / device_code 不走签发准入闸 | password 三件套已删；device_code 已接 `LoginAdmissionService.canLogin` |
| ✅5 | 端点宽松窗口 fail-open | 改为每请求直查 DB，查询失败显式拒绝；启动扫描零写入、仅打漂移告警 |
| ✅6 | authorizedScopes 的 scope claim 装错内容 | 与 scope 同源修复一并解决 |
| ✅7 | **A-P0-1 JWK 每次重启重新生成密钥** | 新增 `PersistentJwkStore`：首次启动生成 RSA/EC 密钥并写入密钥库文件（`iam.jwk.keystore-path`，默认 `~/.iam-platform/jwks.json`），后续启动复用同一份密钥。已验证 kid 跨实例稳定、私钥完整保留、文件权限收紧 600 |
| ✅8 | **A-P0-2 issuer 硬编码 localhost:9000** | 新增配置项 `iam.issuer`（环境变量 `IAM_ISSUER`），`AuthorizationServerSettings`、`JwtDecoder` 校验器、内省 `iss` 属性三处同源引用。`application-prod.yml` 提供生产默认值 |

---

### ℹ️ 已接受的设计决策（暂不改动）

| # | 决策 | 理由 | 触发条件（如果要改） |
|---|---|---|---|
| ℹ️1 | consent 不参与运行时裁决 | 主流 OAuth2 架构均在签发时折叠（granted = 请求 ∩ 注册 ∩ 批准），同意表仅作审计凭证+撤销入口。当前 consent 表全量同意、运行时读了也恒真 | 接入需用户自主授权的真实第三方应用 / 逐项同意合规要求 |
| ℹ️2 | 默认采用 opaque access_token | 撤销（强制下线）功能需要 token 存 Redis，JWT 的无状态优势被抵消；JWT 体积大 37 倍且 payload 可解码泄露 | 资源服务器分散在不同服务且各自有本地存储 |
| ℹ️3 | 种子一次性初始化、上线后以库数据为准 | 页面维护 + 种子初始化双演进会打架 | 需要频繁变更字典的运维场景 |

---

## 九、文档与变更历史

完整变更记录与开发者复盘材料见：
- **CHANGELOG（变更日志）**：[`docs/CHANGELOG.md`](./docs/CHANGELOG.md) — 2026-10-25 至今的所有功能上线/修复/重构记录，含版本号与方案调整历史
- **git log**：更早历史（双服务拆分形态 → 单服务合并形态的完整迁移）

---

## 十、术语表

| 术语 | 含义 |
|---|---|
| allow-list / 未配置即拒绝 | 准入策略：列表中明确列出的才允许，无配置 = 无任何条目 = 拒绝 |
| scope 交集 | 客户端授权范围（scope）展开出的一组权限码，与用户 RBAC 码取交集后注入令牌 |
| 直查 DB | 每次请求都实时查数据库获取准入规则，不缓存到内存 |
| 漂移告警 | 启动时扫描所有 Controller 方法与数据库准入表比对，提示缺失或多余的准入行 |
| 拆表 1:N | 端点准入从一张表拆为资源表 + 绑定表，一个端点可绑定多个权限码 |
