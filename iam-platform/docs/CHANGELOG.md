# iam-platform 变更日志

> 开发者复盘溯源用。**非面向终端用户**。
> 正式文档与当前架构裁定见项目根目录 README.md。

---

## 2026-11-20

### 管理端首页改版为 Dashboard + 说明内容分流 + 界面文案规则

- **内容分流**（index.html 原三块说明迁至对应文档）：「OIDC 令牌分工 / openid 用法 / id_token 三要素」→ `详细设计.md` §4.0；「退出登录对接指南（两步退出、四种场景对比）」→ `接口文档.md` §5.7；「默认客户端类型与 OIDC 支持（四客户端选型卡）」→ `接口文档.md` §5.0.1 客户端类型与选型参考
- **首页重写**：管理端 Dashboard（静态 mock，定位=管控/运维/审计/安全）——① 核心数据概览 KPI×4（账户总数/活跃用户/应用服务/授权调用）② 快捷入口×6 + 最新审计日志（5 行）+ 待办事项（5 项，优先级圆点+页内跳转）；修复原页面章节跳号（删「三、」后「四、」未改号）问题——原说明内容整体迁出后页面不再有章节编号
- **界面文案规则入编码规范**（`docs/编码规范.md`）：「四、编码约定」新增**界面文案**条——静态页/弹窗/提示只写操作性描述，改造历史、原因、裁定编号一律进本 CHANGELOG，不在界面展示（页面源码注释同理）；「六、禁止事项」黑名单同步加一行。存量 9 个静态页 + consent 模板可见文案扫描 0 命中（干净）

## 2026-11-19

### A-P0-1 JWK 密钥持久化 + A-P0-2 issuer 配置化

**A-P0-1（原：每次重启用 UUID 生成新密钥，id_token 全失效）**
- 新增 `net.xzh.iam.auth.security.jwk.PersistentJwkStore`：首次启动生成 RSA(2048)+EC(P-256) 并写入密钥库文件，后续启动解析复用；缺失密钥类型时补齐并保留其它 keys
- `AuthorizationServerConfig.rsaKey()/ecKey()` 改为从该存储取，`jwkSource` 装配不变
- 写盘走「临时文件 + 原子替换」；POSIX 权限收紧 600；解析失败直接启动失败（不静默轮换）
- 配置键 `iam.jwk.keystore-path`（环境变量 `IAM_JWK_KEYSTORE`，默认 `${user.home}/.iam-platform/jwks.json`；prod 默认 `/opt/iam-platform/jwks.json`）
- 验证：两次实例化同一路径，RSA/EC kid 均稳定、私钥字段完整；`JWKSet.toString(false)` 实测含私钥（`toString(true)` 为公钥）

**A-P0-2（原：issuer 硬编码 `http://localhost:9000`）**
- 新增配置键 `iam.issuer`（环境变量 `IAM_ISSUER`）
- 三处同源改造：`AuthorizationServerSettings.builder().issuer(issuer)`、`JwtValidators.createDefaultWithIssuer(issuer)`、`RedisOpaqueTokenIntrospector` 的 `iss` 属性
- `application-prod.yml` 提供生产默认 `https://iam.example.com`，仍以 `IAM_ISSUER` 覆盖
- 遗留：`ALLOWED_REDIRECT_HOSTS`（post-logout 白名单）仍为 localhost 硬编码，归入 A-P1-6
- 升级注意：本次升级后首次启动会生成新密钥，升级前签发的 id_token 失效（原实现本就随重启失效，属预期内一次性影响）；`.gitignore` 已忽略 `jwks.json`

### C-2④ consent 页诚实化 + P1-2 重定为触发式变更包

- consent.html 勾选框假象移除（蓝底方框+cursor:pointer → 灰色圆形 ✓ 静态包含项标识）+ 明示「整体授权，允许=全部授予、拒绝=不授权，暂不支持逐项选择」——与 Keycloak/Auth0 原生全有全无基线对齐（调研：Keycloak #42641 逐项勾选仍在 Backlog、Auth0/Google/Azure 均整体授予）
- P1-2 架构改判：同意按主流做法在**签发时折叠**（granted=请求∩注册∩批准），非运行时查同意表——现状不改（弹页全是演示客户端、consent 表恒真、单独改无效），重写为四件同层触发式变更包（BFF 申请务组→真勾选→自省切 granted→claim 改 granted，硬前置=BFF 补申请务组否则全站 403），触发条件=真实第三方接入或逐项同意合规。
- 实测：consent 页灰圆 ✓ 无指针、诚实说明在位、授予区块正常

### V6.22 占位 scope read/write 全链清除

- 判据=「零消费方」（sys_scope 字典无、/userinfo switch 跳过、Java 字面量 0 命中），非「属原 scope」——openid/profile/email 有协议消费方（id_token/`/userinfo`）保留
- **顺序依赖**：先改 3 个演示客户端请求方（device/web/h5-demo 的 SCOPE 常量）→ 再清注册表（V6.22 迁移 5 行 + 基线 iam.sql 同构）→ 清 Redis db1 存量授权（旧 authorizedScopes 含 read/write，注册表清理后 refresh 会 invalid_scope）→ 重启演示端
- 同步 index.html 三卡片展示值、数据库设计文档客户端表、两个演示 README
- **验证**：全库注册表 read/write=0、业务码仍 17、4/4 令牌内省 `scope=admin.full openid profile`（干净）、设备码流程新 scope 请求通过校验、页面展示 vs 库真值逐项一致

### P0-1 + P2-2 + C-2①②③⑤ 落地（scope 同源 + consent 展示收口）

- `scope` claim 改读**注册表** `oauth2_registered_client.scopes`（RFC 7662 响应 + 内部 `attributes.scope` 两处同源，元数据 scope 先剔除再写入）——实证 admin-app 内省 `scope=read admin.full openid profile write` 与实际授予一致，`/userinfo` 200
- consent 页 `clientName` 改查注册表名、scope 描述改字典驱动（`sys_scope`）、页头按有无业务权限动态文案、**新增「授权后实际获得的业务权限」区块**（`expand(注册表) ∩ 用户 RBAC`，与自省层同源同公式，空映射明示无业务权限）
- C-2④（真勾选）挂起待三层交集裁定
- **部署注意**：计划任务 iam9000 跑 jar，需 `mvn package` 后重启（仅 compile 无效）

---

## 2026-11-18

### V6.20 端点准入拆表（1:N 权限组合）

- `iam_endpoint_policy` → `iam_endpoint`（纯资源行）+ 新建 `iam_endpoint_permission` 绑定表（`endpoint_id CASCADE` / `permission_id RESTRICT` / `uk_endpoint_permission`），56 行搬迁孤儿 0
- 资源行加 `permission_logic`（**ALL=同时具备 / ANY=任一即可**）、顺路删过渡列 `required_authority`/`permission_id`
- 运行时改**每请求三查**（资源→绑定→权限，档位行一查）
- `EndpointPolicyService` 两表同事务写入（`permissionIds` 全集语义）、`EndpointAdmissionManager` 集合裁决、删除守卫切绑定表计数
- 基线 `iam.sql` 同构重写（UNION ALL 回填 56 绑定）
- reset-init verify 表数 17→18，全链复验 PASS（8 项 verify + 6 服务 + 5 健康检查 + 漂移 56=56 + ALL/ANY 日志实锤）
- 8 份文档同步，`required_authority`/`iam_endpoint_policy` 在 java/html/yml/md/ps1 清零（历史迁移文件除外）

### 管理端按钮全站统一

- 8 页刷新按钮 primary 蓝底 → ghost 白底
- 新增按钮半角 `+` → 全角 `＋` 大图标
- endpoint_policy 补缺失的 🔄 刷新按钮
- 弹窗裸 `btn` 取消 → `btn-ghost`
- ghost CSS 灰底无边框变体 → 基准白底描边
- 按钮组加 `flex-shrink:0` 防宽 hint 挤压换行

### README 待办 P2-2 事实更正

- 原文「`attributes.get("scope")` 全 server 0 消费者」系检索模式写死 `attributes.` 而漏检变量名 `attrs` 的误判——实际 `UserInfoController` L63 是消费者（驱动 `/userinfo` profile/email claim）

### 「所属授权范围」放开页面维护

- `sys_scope_permission` 映射行由「仅 SQL 种子」改为**权限码新增/编辑弹窗内勾选维护**
- 组合提交：`POST/PUT /admin/permissions` body 带 `scopeIds` 全集，码与映射在**同一事务**提交
- 组定义 `sys_scope` 仍走种子；保存即时生效

### 准入方案调整（复盘后路线切换：迁移强制 → 页面维护 + 每请求直查）

- `iam_endpoint` 开放页面读写（新增 POST/PUT/DELETE API + 「资源准入」页增删改弹窗）
- 运行时改**每请求直查 DB**，**改权限码零窗口**（实测改名→立即 200 无需重启）、多实例天然同步
- 启动仅打**配置漂移告警不拦截**（配置完整性=运维职责）
- 保留地基（permission_id+FK/policy_type/service_key/扫描零写入/删除双守卫）与**每请求 Fail-Closed**（查询失败一律拒绝）
- 种子定位改为一次性初始化，上线后以库数据为准
- 操作审计升级为上线前必须收口项

### P0-2 接口准入一致性与多实例启动安全落地（包0-3）

- V6.17 迁移 `permission_id` 化 + FK RESTRICT + `policy_type` + `service_key`
- 启动改**只读加载 + 双向严格校验**（接口有表无 / 表有接口无 / 权限ID不存在 → 一次性列全明细、拒绝启动）
- **进程内三态门禁**（INITIALIZING/FAILED 一律拒绝不降级认证档）
- `updatePermission` 改名守卫按 permission_id 放开、`deletePermission` 切 id 源并补双守卫

---

## 2026-11-17

### SSO 准入拒绝后重新登录恢复原始授权请求

- SavedRequest：拒绝码带 `continue` 回跳原授权请求，不再落首页

### V6.16 `zhangsan` 种子迁移

- 补执行存量库（设备码放行路径依赖 THIRD_PARTY 种子用户；新库走基线 iam.sql 幂等跳过）

### C-1 客户端治理聚合落地

- 删除菜单与页面「登录准入」「授权范围」（`login_policy.html` / `scope.html`），登录准入配置与 scope 字典明细并入「客户端管理」编辑弹窗
- 资源准入页补「所属授权范围组」反查
- **菜单/页面 = 前端静态文件，表、种子、写接口零变化**

---

## 2026-11-04

### 设备码签发准入闸

- `DeviceCodeGrantAuthenticationProvider` 用户激活确认后调 `LoginAdmissionService.canLogin`，未命中 `access_denied` —— 设备码不经 `/oauth2/authorize`，此前 `client_login_policy` 对其不生效

### 密码模式三件套删除

- `PasswordGrantAuthenticationConverter`/`Provider`/`Token` 及装配、`passwordEncoder` 参数、`test.http` 示例全部移除
- OAuth 2.1 废弃该授权类型且无客户端注册

### 登录准入模块上线

- `client_login_policy` 表（client × 主体 allow-list）+ `LoginAdmissionService` + `AdminLoginPolicyController` + 管理页 `login_policy.html`
- 签发准入由「权限码交集」改为「准入表裁决」，登录/授权两层解耦，`IssuanceAdmissionService` 删除
- README 待办新增 A 组「架构设计问题」

### 种子收敛

- 种子 `device-app` 登录准入收敛为仅 `THIRD_PARTY` 角色（原对所有登录用户开放）
- 新增种子用户 `zhangsan`（THIRD_PARTY，0 权限码）

---

## 2026-10-27

### 旧机制批量退役

- 删除 `iam_endpoint` 的 `domain`/`source` 两列及其页面增删改
- 删除 `sys_permission.domain`（业务分类改用 `remark` 前缀）、`sys_scope.domain`
- 删除客户端信任闸 `clientWhitelistGate`、`AuthServerProperties` 整类、`application.yml` 三段白名单配置
- 删除粗档常量 `ADMIN_SERVICE_TOKEN`/`PORTAL_SERVICE_TOKEN` 及 M2M 服务令牌分支
- 删除 `sys_user.user_label` 列及其校验、展示、"降级猜测"逻辑
- 签发准入 `IssuanceAdmissionService` + `AuthorizeIssuanceFilter` 新增（混合登录隔离）
- 权限码 `policy:read`/`policy:write`/`portal:client:read`（承接原粗档端点），权限码总数 14→17
- 双服务遗留命名清理：`PortalUserDetailsService`→`PlatformUserDetailsService` 等

---

## 2026-10-26

- 数据库 / Redis 地址 `192.168.43.161` → `192.168.31.161`
- `admin-app` 密钥异常态恢复为基线 `123456`（经 SQL 直写 + 清 Redis）

---

## 2026-10-25

### 双维权限控制上线

- `sys_scope`/`sys_scope_permission` 两表、`ScopeService`、`AdminScopeController`(只读 GET)、只读页「授权范围」
- 自省层按「用户码 ∩ 客户端 scope 码」注入业务权限码
- 删除 `iam_client_policy` 表及其 8 个 Java（ClientPolicy 族 / AuthorizePolicyFilter / 两个 PolicyAware provider）、`policy.html`
- 「客户端管理」页 scopes 改为授权范围勾选
- 「权限管理」页增加「所属授权范围」列

---

## 更早历史

> 双服务拆分形态（认证中心 + 资源中心）→ 单服务合并形态的完整迁移记录见 git log。
