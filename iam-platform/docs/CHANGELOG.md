# iam-platform 变更日志

> 开发者复盘溯源用。**非面向终端用户**。
> 正式文档与当前架构裁定见项目根目录 README.md。

---

## 2026-11-20

### A-P0-3 拆弹：OIDC 动态客户端注册 (DCR) 端点关闭

- **事实修正**：原审计「任何人 POST 即可注册客户端」经端到端探测不成立——过滤器实际**未装配**（discovery 未通告 `registration_endpoint`、`OidcConfigurer` 字节码证实惰性装配且本项目未调用、空体 POST 落到 CSRF 403）。但 settings 路径行 + permitAll 许可构成「引信」：未来任何一行代码装配过滤器即裸奔。
- **双层收口（方案 A）**：① permitAll 名单摘除 `/oauth2/connect/register`；② 新增 `ClientRegistrationDenyFilter`（`auth.security.web`，`OncePerRequestFilter`）置于协议链 `SecurityContextHolderFilter` **之前**——对配置路径 `/oauth2/connect/register` 任意 HTTP 方法直接返回 404，响应体模仿 Spring Boot 默认错误格式（探测者无法区分「被拒」与「不存在」）；settings 路径行保留（显式可审计）+ 注释注明刻意关闭。
- **为什么删 permitAll 不够**（关键认知）：启动日志证实 SAS 端点过滤器位于 `AuthorizationFilter` **之后**——删 permitAll 只挡匿名请求，**已登录会话仍穿过授权层进入注册过滤器**；且 CSRF「意外拦截」随 SAS 装配自动豁免而消失（SAS 为已装配端点自动加 CSRF 豁免）。拒绝过滤器与装配状态、过滤器顺序、CSRF 豁免均无关。
- **【校正】** 上一条方向正确，此前一版【校正】（称 `addFilterBefore`、实为「之前」）系看错 Configurer——**终审取证（javap 全量提取 SAS 1.4.1 boot jar 内 11 个 `*EndpointConfigurer`）**：`OidcClientRegistrationEndpointConfigurer` 与令牌/内省/撤销/用户信息/设备授权端点均为 `addFilterAfter(AuthorizationFilter)`（在授权层**之后**）；`addFilterBefore` 的是授权/设备验证/登出/OIDC 元数据端点，且锚点为 `AbstractPreAuthenticatedProcessingFilter`/`LogoutFilter`，非 `AuthorizationFilter`。旁证：本项目 `/oauth2/token`、`/oauth2/introspect` 必须放 permitAll 才可用——若在之前则这些许可无必要。故正确论证 = **删 permitAll 只挡匿名，已登录会话仍穿过授权层**。另：`/connect/register` 不在任何安全链 securityMatcher 内，其 404 来自「无链匹配 + 无 MVC 路由」，非过滤器拦截；该分支保留为未来协议链 securityMatcher 扩展时的保险。
- **验证**：匿名 POST/GET 配置路径 → 404；默认路径 POST → 404；**已登录同源 POST → 404**（关键用例）；discovery/jwks/introspect(`{"active":false}`)/登录链/管理 API 5×200 全正常。README A-P0-3 移入已解决表 ✅9；`详细设计.md` §1.1 补「DCR 关闭」小节。

### A-P0-4 拆弹：表外端点运行时降级翻转为 fail-closed

- **改动**：`EndpointAdmissionManager` 的 `rule == null` 分支（未配准入行）由「认证档放行（有效内省令牌即过）」**翻转为一律拒绝 403**，日志 `debug` → `warn` 且**按路径去重**（每路径首见 warn、后续 debug，防扫描刷日志）。类 javadoc「表外」行同步。
- **D1 裁定收敛（非推翻）**：D1 保留**启动维度**（启动不阻塞、`EndpointPolicyScanInitializer` 漂移告警提示补行）不变，仅改判**运行时子句**（请求侧不再降级）——D1 管"启动不拦"，deny 管"请求不放"，两者不冲突。开发流程不变：新端点忘配行 → 启动漂移告警 + 页面可见 → 补行保存即时生效；漏看的后果是 403（fail-closed）而非静默裸奔。
- **零现实回归依据**：启动漂移检查连续实测 56 接口 = 56 准入行无漂移，null 分支从未执行过——把一个从没走过的分支从放行改拒绝，对现有功能零影响；`/permitall/**` 链层短路不进管理器；未映射路径 404→403 无数据差异。
- **三方立场收敛**：原 D1（认证档=配置缺省）/ 审计 A-P0-4（P0 fail-open）/ README §六「任一缺口即拒绝」互斥 → 方案 A 落地后代码与 fail-closed 承诺一致，README P0 表**清零**（A-P0-4 移入已解决 ✅10）。
- **文档同步**：README（P0 表清零 + ✅10 + 数据表行）、详细设计 §5.2/§5.3、权限与安全设计（④ 层 + 裁决表 + 包路径行）、数据库设计文档（两步流程）、操作说明（排查 403 + 新端点章节）——所有"表外走认证档"表述改为"拒绝 403，补行即生效"。
- **验证**（打包重启 9000 后实测）：
  - **新行为**：带有效令牌（授权码流程真实 access_token）直连 9000——`GET/POST /admin/__ap04_no_row_test`、`GET /biz/__ap04_no_row_test`（三前缀下无准入行路径）→ **403** `{"code":403,"msg":"无权访问"}`（改前该场景被认证档放行落 MVC 404）；经 8001 BFF 同测 → 403。
  - **零回归**：表内端点 `GET /admin/users`、`/admin/endpoint-policies` 直连 200，8001 BFF 会话下 `/admin/users|roles|clients|endpoint-policies` 4×200；完整登录链（8001→8085 OAuth→9000 授权→回调）走通；`/permitall/time` 200（链层短路不受影响）；discovery/jwks 200；匿名态 9000 各路径 401（与改前一致）。
  - **行为差异（fail-closed 方向，记录备查）**：三前缀下**未在准入表注册的方法**（如 `HEAD/OPTIONS /admin/users`——表内只有 GET 行、扫描器按 `@XxxMapping` 注解方法生成行、HEAD 为 Spring 隐式支持不入表）改前走认证档落 MVC（HEAD=200/PUT=405），改后统一 **403**。平台内无 HEAD/OPTIONS 消费方（前端/BFF 脚本全量扫描 0 命中），9000 未配置 CORS（无跨域预检），无实际影响；语义上与"未配行即拒绝"自洽。

### A-P1-1 拆弹：client_credentials (M2M) 接口层封死

- **定性**：非现实漏洞（实测 DB 0 个 client_credentials 客户端、无 M2M 消费方），而是**半拆残留的引信**——M2M 方案已废弃（概要设计决策#1 单体无服务间调用 + 静态环境变量凭证不可轮换/审计，CHANGELOG 2026-10-27 已删凭证），但令牌端点转换器/provider、管理页选项、V6.9 迁移均未清理。原"三重保险"（无客户端/0 业务码/A-P0-4 deny）全是数据与实现巧合，非代码规则。
- **四层封死（方案 A）**：① `accessTokenRequestConverters(converters -> removeIf CC)` 从默认列表摘除转换器；② `providers.removeIf(OAuth2ClientCredentialsAuthenticationProvider)` 双保险；③ `client.html` GRANT_TYPES 删选项；④ `ClientService.validate` 服务端拒绝（返回业务 400，防 API/直库绕过）。
- **【关键坑】转换器摘除必须用复数 Consumer 方法**：单数 `accessTokenRequestConverter(...)` 字节码为 `List.add` **追加语义**，SAS `configure()` 中 `createDefaultAuthenticationConverters()`（含 CC）**永远先构建**、自建列表只是 `addAll(0, ...)` 插到前面——首轮按单数方法摘除属**无效操作**，实测表现为 `grant_type=client_credentials` → **302 login**（默认 CC 转换器认领请求 → provider 已摘 → 无 provider 异常冒泡 → ExceptionTranslationFilter → 登录页）而非 400；改用复数 Consumer（字节码证实其在默认列表构建**之后**执行）后 → 标准 **400 unsupported_grant_type**。
- **顺手清理**：重复注册两次的 `OAuth2AuthorizationCodeAuthenticationConverter`（原 L364/365）；`AdminClientApiController` javadoc 中已废弃的 `ADMIN_SERVICE_TOKEN` 表述；V6.9 迁移头部加「已废弃·勿重跑」警告（重跑会插入换不到令牌的死客户端）。
- **验证**：`grant_type=client_credentials` → 400 `unsupported_grant_type`（与无效 grant `foo` 同行为）；`authorization_code` 缺参 → 400 `invalid_request`（对照）；创建带该 grant 客户端 → 业务 400「不支持 client_credentials (M2M) 授权模式」；正常客户端创建/删除 → 200（DB 无残留）；设备码入口 200、授权码登录链（8001→8085→9000→回调）走通、管理 API 3×200。
- **恢复路径**（将来真有 M2M 需求）：一次代码 PR（加回①②+UI 选项+放开校验）→ `m2m.*` scope 入 `sys_scope` + 交集逻辑对 client_credentials 改 scope 展开直作业务码（核心设计点）+ 端点准入行 + 服务身份审计 + 凭证轮换 → 概要设计/权限与安全设计决策先行改写。

### A-P1-2 拆弹：登录防爆破 (Redis 失败计数 + 临时锁定)

- **现状事实**：登录端点零防线——无失败计数、无锁定触发方（`sys_user.account_non_locked` 字段存在且已接进 `UserDetails`，但全代码无任何处置 0 的地方）、无限流设施、**失败连一行日志都不打**（被爆破事后无从得知）；`/login` POST 在 CSRF 豁免清单（静态登录页无法渲染 token），攻击者裸 POST 即可。`client_login_policy` 登录准入只管"哪个客户端"，不管"猜了几次"，维度不同帮不上。
- **方案 A 落地（三层）**：① `LockoutAuthenticationProvider`（`auth.security.lockout`）装饰 `platformDaoProvider`——认证前 user/IP 双维度锁定检查（**正确密码也拒绝**）+ 成功清计数与 info 日志；两条表单链单点覆盖。② `LockoutAwareFailureHandler`——失败计数 + 锁定/普通失败分流（normalUrl 与改前基线逐字节一致）。③ 登录页 `error=locked` 分支：「登录尝试过多，请 N 分钟后再试」（retry 分钟数由跳转 URL 携带，随配置走）。
- **【关键坑】失败计数必须放 FailureHandler，不能放认证装饰器**：失败路径上本地与父级 ProviderManager 会**先后调用同一装饰器**（本地抛 BadCredentials 后父级回落复用 bean），INCR 翻倍——首轮实测每次失败 +2，**第 3 次请求即达阈值 5**（增量探针：failure#1→计数 2、#2→4、#3→5+锁定）。Spring 对每个失败请求**恰调用 FailureHandler 一次**，与 AuthenticationManager 拓扑无关。成功路径本地命中即返回不回落父级，故成功清计数留在装饰器是安全的（恰一次）。
- **参数（`iam.login-guard.*`，application.yml 可调）**：计数窗口 600s（固定窗口，首见设 TTL）；账号阈值 5 → 锁 900s；IP 阈值 20（防喷洒、容忍共享出口/NAT）。**解锁 = Redis TTL 自然过期**——锁定机制不被反向利用为 DoS（攻击者零成本锁死真账号的场景被 TTL 上限压到 15 分钟）；管理员人工升级通道 = 已有的「禁用账号」（`enabled=0`），与自动锁正交，无需新做手动解锁。
- **防抖与边界**：触发锁定即清零该维度计数（防"解锁瞬间旧计数二次触发"）；成功仅清用户名计数、IP 计数保留至窗口过期（否则攻击者持一个合法账号即可重置喷洒计数）；仅 `BadCredentialsException` 计数（Disabled/CredentialsExpired/内部错误不计，防 DB 故障误锁）；锁定期内尝试不再累计（锁不被延长）；用户名归一化小写（与 MySQL ci 排序规则一致，防大小写绕过）。
- **审计第 1 层（log 级，本单交付）**：失败 `log.warn`（用户名 + IP + 双维度计数 x/阈值）、锁定触发 `log.warn`、成功 `log.info`。**登录历史落库 + 查询页归 A-P1-3**（与敏感操作审计统一设计，避免重复建表），已在 README A-P1-3 条目标注。
- **验证（13/13）**：改前基线跳转逐字节一致（`/login.html?error`、`/login.html?type=device&error`）；失败 1-4 正常跳转、**第 5 次触发锁定**（`error=locked&retry=15`）；**第 6 次正确密码仍被拒**（核心用例）；Redis 锁 key TTL=900、计数清零；清 key（模拟 TTL 解锁）后正确密码恢复 302；20 次跨账号喷洒触发 IP 锁、锁定期内 admin 正确密码同样被拒；完整登录链（8001→8085→9000→回调）/设备码入口/管理 API 3×200/discovery 200 回归正常；全部 guard key 已清理。
- **备注**：`boot9000.log` 中中文日志显示为替换符——实测改造前既有中文日志（EndpointPolicy 等）同样乱码，属 `schtasks+cmd 重定向+JVM 控制台编码` 的**环境既有问题**，非本改动引入（判定依据：新旧日志行均含 U+FFFD，表现一致）。

### A-P1-4 拆弹：SSO 会话并发封顶 (maximumSessions 5 + 踢旧)

- **改动**：两条链（主 SSO L428、设备验证 L471）`maximumSessions(-1)` → **`maximumSessions(5)`**。共享 `RedisSessionRegistry` 按 principal 计数不分链，两链必须同值对称（否则设备链 -1 不检查但照常计数）。默认语义 `maxSessionsPreventsLogin=false`：第 6 次登录总是成功、踢掉最旧会话——**永不锁死自己**（受害者重登即挤掉攻击者旧会话，正是被盗恢复动作）；`maxSessionsPreventsLogin=true` 反而是陷阱（攻击者占满后受害者登不进），刻意不用。
- **【执行中修掉的隐藏缺陷 ①】封顶首轮实测不生效**（6 连登 → 活跃 6、踢 0）：字节码取证 `ConcurrentSessionControlAuthenticationStrategy.allowableSessionsExceeded` 踢出时只调 `SessionInformation.expireNow()`（内存布尔），而本项目注册表**每次从 Redis 重建临时对象**——标记不回写即丢，`SessionExpirationFilter` 永远检测不到 → 踢不出去。**修复**：自定义 `RedisSessionInformation` 覆写 `expireNow()` 同步写 Redis `expired=true`（与既有 `markSessionExpired` 同一存储位，幂等不改 TTL）。
- **【执行中修掉的隐藏缺陷 ②】被踢落点不带 `?expired`**：DEBUG 启动日志过滤器链取证——`SessionExpirationFilter` 排在 `ConcurrentSessionFilter`（`expiredUrl` 唯一消费者，`SimpleRedirectSessionInformationExpiredStrategy`）**之前**，且先 `removeSessionInformation` + `invalidate` → CSF 查不到过期记录 → **`expiredUrl` 是死配置**，实测被踢落裸 `login.html`，用户无从得知被踢原因。**修复**：`SessionExpirationFilter` 改为显式 `saveRequest`（与 ETF 默认同 `SPRING_SECURITY_SAVED_REQUEST` 属性）+ 带 `?expired` 跳转——同时保住「可感知提示」与「重登回原流程」（原设计靠继续链由 ETF 保存请求，改为显式保存后两者兼得）。
- **登录页**：`login.html` 补 `expired` 分支——「会话已过期或已在其他设备登录，请重新登录」。
- **验证**（verify3 6/6 + final 4/4 + 全量回归）：6 连登 → **活跃=5、踢 1**（Redis `expired=true` 持久化）；被踢会话持有效授权请求（含 PKCE）→ **302 `login.html?expired`**（认证已清）；**同一浏览器重登 → 恢复原授权请求**（state=finalstate 一致，SavedRequest 生效）；活跃会话正常发 code；新登录不被拒；完整登录链（8001→8085→9000）/管理 API 3×200/设备码/登录防爆破（错误密码仍 `login.html?error`）全回归。
- **脚本侧两坑记录**：① Spring Session cookie 值是 **base64 编码的 sid**，直接比对注册表 UUID 会误报不匹配（解码后一致）；② 首轮验证用无 PKCE 的授权请求，授权端点在校验阶段即报 `invalid_request`（早于会话检测），被踢/活跃两组结果无区分度——补全 PKCE 后用例才有效。

### A-P1-5 拆弹：dev/local 配置占位符化（DB/Redis 凭据可覆盖）

- **改动（3 文件，零行为变化）**：① `application-dev.yml` / `application-local.yml`（两文件内容原本完全相同）—— datasource 三项 `${DB_URL:现值}`、`${DB_USERNAME:root}`、`${DB_PASSWORD:123456}` + Redis 三项 `${REDIS_HOST:现值}`、`${REDIS_PORT:6379}`、`${REDIS_PASSWORD:}`；② `iam-admin-bff/application.yml` Redis 段同样处理（单文件无分层）。**默认值=现值 → 不设环境变量时行为逐字节不变**，schtasks 启动命令不改、clone 即跑；环境变量名与 prod profile 既有占位符**同名**（`DB_URL/DB_USERNAME/DB_PASSWORD/REDIS_HOST/REDIS_PORT/REDIS_PASSWORD`），跨 profile 覆盖方式一致。
- **【事实修正】原影响描述有一半不成立**：README 称「生产部署必须手动改配置文件」——实测 `application-prod.yml` **本就是全占位符**（`${DB_URL:...}`、`${DB_PASSWORD:CHANGE_ME}`、`${REDIS_PASSWORD:CHANGE_ME}` 等 10 处），prod 不需要手改。真实剩余风险两条：① **仓库泄露 → 内网 root 凭据泄露**（MySQL root + `123456` + 内网 IP，网络可达即整库失守）；② dev/local 场景换环境手改文件 → **改过的文件可能被 git 回提交**（新环境密码反向写进仓库）。本项对症 ②（可覆盖、不改文件），① 靠「演示库不放真实数据 + 内网隔离」兜底——**密码仍可见于仓库是零摩擦开发的刻意取舍**。
- **方案取舍记录**：方案 B（密码无默认值）——仓库彻底无密码但 schtasks 要塞环境变量（密码换地方存进计划任务 XML）、开发者 clone 跑不起来，对演示项目过重；方案 C（gitignored `application-secrets.yml` + `spring.config.import`）——密码真正出仓库但配置链多一层。**用户拍板 A**；将来若仓库要公开/接入 CI，升级路径 = A→C（占位符已就位，只需去掉默认值 + 加 import）。
- **范围外澄清**：README/接口文档中的 `123456`（admin-app 密钥、演示用户密码）是**文档明示给使用者的演示凭据**，非配置泄露，不在本项；`iam-portal-bff` 无 Redis 配置（内存 session），不涉及。
- **占位符生效实证**：临时实例 `-DDB_PASSWORD=WRONG_PLACEHOLDER_PROOF --server.port=9001` → 日志 `java.sql.SQLException: Access denied for user 'root'@'192.168.31.78'` —— 系统属性覆盖默认值、传到 JDBC 的链路确凿（启动不 fail-fast 是 Druid 建连重试语义，不影响证明；实例已清理，9001 无残留）。
- **环境附带修复（中断恢复）**：本轮跨中断恢复时 8085 计划任务指向的 `start_bff8085.bat` 已被 Temp 清理、9000 也停了——重建 bat（java -jar 方式，与原 mvn spring-boot:run 等价、jar 已含占位符）并按「先 9000 后 8085」顺序拉起（8085 首启因 9000 未就绪、OIDC discovery Connection refused 失败，重试即成——**BFF 启动依赖 9000 的时序问题**，与本项无关但记档）。
- **回归**：完整登录链（8001→8085→9000 授权码）走通、管理 API 3×200、discovery 200、设备码 200。

### A-P1-6 拆弹：登出回跳目标校验（open redirect 堵死 + 数据源改客户端登记表）

- **【事实修正】审计结论又是反的（与 A-P0-3 同款：只读常量、没追调用链、没实测）**：`ALLOWED_REDIRECT_HOSTS`（14 项 localhost 端口）+ `isRedirectAllowed()`（javadoc 明写"防止 open-redirect 漏洞"）**全库零调用——死代码**；README 所述"非 localhost 端口全被拒、上线必炸"**永不发生**。
- **真实问题恰是反面——open redirect 活洞**：`LogoutController` 对 `post_logout_redirect_uri`/`redirect` 参数直接 `sendRedirect` 零校验。改前实测：`?redirect=https://evil.example.com/phish` → 302 直通；`?redirect=//evil.example.com` → 302 到 `http://evil.example.com`（协议相对绕过）；且 SAS 自带会校验 post_logout URI 的 `OidcLogoutEndpointFilter` 被自定义控制器刻意绕过（id_token_hint 解码 bug）——规范层兜底也没有。钓鱼场景：伪造"认证中心登出链接"→ 受害者被登出 + 跳钓鱼站，"刚登出"的跳转天然可信。
- **A″ 方案（用户否决硬编码白名单接线，改为按客户端登记地址校验——OIDC RP-Initiated Logout 规范做法）**：跳转前三源判定，任一命中才放行，全不中 → 不跳转落「登出成功」页 + `log.warn`（记目标与来源 IP）：
  - ① 同源相对路径（`/` 开头，排除 `//` 与 `/\` 协议相对变体）→ 放行（跳不出本站）；
  - ② 绝对 URL（仅 http/https，拒 javascript:/data:/畸形）→ **逐字匹配**某注册客户端的 `post_logout_redirect_uris`——数据源 = `oauth2_registered_client` 表（「客户端管理」页维护），**零硬编码、零新配置，换环境改登记地址不改代码**；
  - ③ 携带 `id_token_hint` → 解 JWT payload 的 `aud` **收窄到该客户端自己的登记地址**（跨客户端地址也拒）。**不验签**的安全性：伪造 aud 最多在各客户端已登记的合法地址间切换校验范围，永远跳不出登记表——主防线是②；解码失败退化 union，不影响主防线。
  - 附带：`state` 追加前 URLEncode（防参数拼接注入）；删除死代码（常量+方法+`java.net.URI` import）。
- **调用方全量核对**：portal-bff（带 hint，目标 8000/logged-out ✓ portal-app 已登记）、admin-bff（目标 8001/logged-out ✓ admin-app 已登记）、web-demo（`redirect=http://localhost:8081/`，**原登记不含此地址 → 配套数据修正**）、h5-demo/device-demo 本地登出不涉及。
- **配套数据修正（V6.23）**：oa-web-app 补登记 `http://localhost:8081/`——base `iam.sql` + 新迁移 `V6.23__oa_web_app_logout_uri.sql`（幂等 `NOT LIKE '%,http://localhost:8081/'`，初版 `NOT LIKE '%http://localhost:8081/%'` 会误匹配已有 `/logout` 前缀导致永不执行，已修正）+ 现库已同步（rows updated=1）。
- **验证 13/13 + 回归**：evil 绝对地址/`//evil`/`javascript:`/标准参数 evil → 全部 200 落成功页无 Location；跨客户端 hint（target=8000 但 aud=oa-web-app）→ 拒；同客户端 hint（target=8001，aud=admin-app）→ 302 ✓；坏 hint → 退化 union 放行已登记地址；portal/admin/web-demo 三真实登出流 302 正确；同源相对路径 → 302 补全为本站绝对地址（Servlet sendRedirect 规范行为）；state=`x&injected=1` → `state=x%26injected%3D1` 注入被编码；无参 → 成功页；完整登录链/管理 API 3×200/discovery/设备码回归全绿。
- **文档**：README A-P1-6 移入 ✅15（P1 表**仅剩 A-P1-7**）、接口文档 §5.7 补回跳校验说明（新增客户端/换环境在管理页登记即可，无需改代码）。

### A-P1-7 拆弹：device/verify 400（TC-12）—— 复现、根因、友好错误回落

- **复现（README 要求"接手先复现"）**：矩阵探测确认**仍存在**——GET/POST 只要带 `user_code` 参数（格式对/错/空、真码/假码）→ **400 白标 JSON**；不带 → 正常 302 登录。日志**无任何异常堆栈**（白标 400 = `sendError`，非异常冒泡）。
- **根因（字节码取证）**：SAS `OAuth2DeviceVerificationEndpointFilter` —— matcher = `(GET|POST) AND user_code != null`（解释"带参才 400"）；converter `validateUserCode` 格式校验 / 查 pending 记录；**任何** `OAuth2AuthenticationException`（格式错/码不存在/已过期）→ 默认 `authenticationFailureHandler` → `response.sendError(400)` → Spring Boot 白标错误页。
- **影响面确认（比"已知 bug"字面窄）**：真实设备流程**完全正常**——真码未登录 → 302 登录（SavedRequest 保留）、已登录 → 302 同意页（流程推进）；**用户可达的坏路径** = `device-activate.html` 表单**直 POST** 到该端点，用户在 /activate 输错码 → 工程师风格白标 400（无任何"代码无效"提示）。**纯 UX 缺陷，无安全影响，设备功能未坏**。
- **修复（方案 A，3 处）**：① `deviceVerificationEndpoint(dv -> ... .errorResponseHandler(...))`——SAS 公开的定制口（javap 确认）→ 验证失败 **302 回 `/activate?error=invalid_user_code`**，覆盖表单直 POST、GET 重定向（DeviceActivateController L80）、直访三种路径；② `device-activate.html` 补错误提示条 + JS 读 `error` 参数（该页原本**零错误显示能力**，只有表单）；③ 真码流程不受影响（失败处理器仅异常时触发）。
- **验证 10/10 + 回归**：坏码矩阵（GET/POST × 格式错/假码/空码）全部 **302 带 error 回输码页**（改前全 400）；真实流程 3 步不变（device_authorization 200 → 未登录 302 登录 → 已登录 302 同意页）；输码页 200 且 alert div/JS/文案齐备——**首轮 2 项误报教训**：`/activate` 在设备链读 `DEVICE_SECURITY_CONTEXT`，主链 `/login` 的 cookie 不被接受，须走 `/device-login` 设备链登录后才能取到页面；登录链/管理 API 3×200/设备码/discovery 回归全绿。
- **文档**：README A-P1-7 移入 ✅16——**P1 表仅剩 A-P1-3（用户明示跳过项，登录历史审计已归入其下）**。

### README 待办补录（修复上轮重排丢失的 6 项）

上轮「按代码审计重排待办」误删若干条目，按当前事实核实后补回（不照抄旧文，逐项复核状态）：

- **A-P1-7** `device/verify` 返回 400（TC-12 已知 bug，根因未排查；标注"接手先复现"）
- **A-P2-7** 代码卫生残留（resolveDomain 判空用途、`/users/{code}/data` 死接口、iam.sql capability 死块 + iam_client_policy 遗留 DROP）——原同条的孤儿权限码 `policy:write` **核实已不成立**（V6.18 已建 3 条端点行），剔除
- **B-10**（触发式）三方域首个业务端点开通（触发时必须先补 sys_scope_permission 映射 + 端点准入，否则恒 403）
- **B-11** 文档配图（IMG-1~6 / SHOT-1~9 清单在各文档、产出全无）
- **⛔ C-1 三条铁律**恢复为 B 组前置约束块——尤其铁律3「聚合写必须先落操作级审计」：P0-2 引用完整性已 ✅、A-P1-3 未做 → **约束当前生效**（重排后 B-4 编号已他指，铁律引用同步改为 A-P1-3）
- **原「YAML 配置分类」**：按 auth/resource 拆分的旧设想已随单服务合并过时，其实质（密码硬编码→环境变量）已由 A-P1-5 覆盖，在该条目内注明继承关系，不单列
- **原「用户编码字段治理」**：user_code 格式统一**实测已完成**（存量 3 用户全标准 UUID，`check` 脚本核验）；剩余的 username/principalName 双职分离属**活约定**，落入 `编码规范.md` 命名表「展示与取值分离」行，不挂待办

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
