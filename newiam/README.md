# newiam — iam-platform 形态重构目标工程

按"唯一 Owner"原则重构后的新工程。旧工程 `../iam-platform` 保持只读不动，仅作为迁移来源；割接日本目录扶正为 `iam-platform`。

---

## 一、目录结构总览

```text
newiam/
├── README.md                           # 本文件：结构说明 + 端口规划 + 边界裁定
│
├── server/                             # ──【服务端】Java · Spring Boot 3.4 核心服务──
│   ├── iam-common/                     #   公共基建（Result/异常/Properties 基类），纯类库无端口
│   ├── iam-gateway/                    #   :8080  API 网关，外部流量唯一入口
│   ├── iam-auth-server/                #   :9000  认证中心（协议运行时，iam_identity 独占写）
│   ├── iam-access-service/             #   :9010  权限中心 PDP + 平台资产域（iam_authorization 独占写）
│   ├── iam-identity-service/           #   :9020  身份管理面（无库，经内部 API 写）
│   └── iam-open-service/               #   :9030  开放平台（iam_open 独占写）
│
├── bff/                                # ──【体验面】Java · OAuth2 Client，均无库──
│   ├── iam-portal-service/             #   :8100  门户 BFF（portal-app，PKCE）
│   └── iam-admin-service/              #   :8101  管理 BFF（admin-app，透传代理）
│
├── web/                                # ──【前端】静态站──
│   ├── iam-portal-web/                 #   :8200  门户前端
│   └── iam-admin-web/                  #   :8201  管理后台前端
│
├── clients/                            # ──【客户端示例】Node.js 零依赖第三方接入 demo──
│   ├── iam-client-web-demo/            #   :8300  授权码+密码模式（web-app）
│   ├── iam-client-device-demo/         #   :8301  设备码 RFC 8628（device-app）
│   └── iam-client-mobile-demo/         #   :8302  授权码+PKCE（mobile-app）
│
├── sql/                                # ──【数据库脚本】按库分组（v2 并行库，旧栈不受影响）──
│   ├── iam_identity_v2/                #   认证中心库（auth-server 唯一写者）
│   ├── iam_authorization_v2/           #   权限中心库（access-service 唯一写者，含迁入的 client_policy）
│   └── iam_open/                       #   开放平台库（open-service 唯一写者，新库）
│
├── scripts/                            # ──【脚本】启动/编排──
│
└── docs/                               # ──【文档】设计文档与架构图──
```

---

## 二、端口规划（重新定义，按层分段）

```text
8080          网关入口段      iam-gateway（唯一对外入口）
8100 ~ 8199   体验面 BFF 段    portal=8100  admin=8101
8200 ~ 8299   前端静态站段     portal-web=8200  admin-web=8201
8300 ~ 8399   客户端示例段     web=8300  device=8301  mobile=8302
9000 ~ 9099   服务端核心域段   auth=9000  access=9010  identity=9020  open=9030
```

> 迁移约束：端口全部重新编址，旧工程的 redirect_uri、回调地址、application.yml、
> 种子数据中的端口引用，迁移时必须按新端口段同步更新。

---

## 三、模块职责（唯一 Owner）

### 服务端

| 模块 | 库 | 职责 |
|---|---|---|
| iam-common | — | Result/异常/公共 Properties（仅基础设施，禁放领域类） |
| iam-gateway | 无 | 外部流量唯一入口（验签/限流/计量挂载点），本期只挂 `/api/open/**` 路由组 |
| iam-auth-server | iam_identity_v2 | 协议运行时：OIDC/OAuth2 端点、登录登出同意、token 生命周期、client 注册、`/api/internal/**` 供给 API |
| iam-access-service | iam_authorization_v2 | 权限中心 PDP：RBAC + 统一准入策略（client_policy + endpoint_policy + decide 问询）+ 平台资产域 |
| iam-identity-service | 无（经内部 API 写） | 身份管理面：用户/租户/客户端/会话管理 API、跨域编排（删用户联动）、外部身份绑定 |
| iam-open-service | iam_open | 开放平台：能力目录、订阅、开发者/三方应用档案、计量配额（骨架） |

### 体验面 / 前端 / 客户端示例

| 模块 | 职责 |
|---|---|
| iam-portal-service | 门户 BFF：OAuth2 Client(portal-app)+手动 PKCE、独立会话、心跳自省、RP-Initiated 登出 |
| iam-admin-service | 管理 BFF：OAuth2 Client(admin-app)、通用透传代理（按路径分流 auth/access/open） |
| iam-portal-web / iam-admin-web | 静态前端，无逻辑 |
| iam-client-*-demo | 三种 OAuth2 接入姿势演示（授权码+密码 / 设备码 / PKCE） |

---

## 四、关键边界裁定

1. **双面分离**：auth-server=运行时，identity-service=管理面；iam_identity 单一写者=auth-server，管理面只经内部 API 写。
2. **所有"能不能"归 access（PDP）**：登录改为 decide 问询（SWR 缓存），退役 internal roles 接口与 user_label 猜测。
3. **对外卖的归 open，自家用治理留 access**：capability/subscription 迁入 iam-open-service + 新库 iam_open。

---

## 五、命名规范

| 项 | 规范 |
|---|---|
| 模块名 | `iam-<域>[-<层级>]`；server 层后缀 `-service`（common/gateway 除外），层级同时由目录编码 |
| 认证/准入对偶 | auth-server=认证（你是谁），access-service=准入（你能做什么），不使用 authz 缩写避免混淆 |
| groupId / artifactId | `net.xzh` / 与目录名一致 |
| 基础包名 | `net.xzh.iam.<短名>`：common · gateway · auth · identity · access · open · portal · admin（替换旧工程不统一的 authserver/resource/admin 包名） |
| 库名 | iam_identity_v2（auth 独占写）、iam_authorization_v2（access 独占写，authorization 恰为 PDP 精确语义，含迁入的 client_policy）、iam_open（open 独占写）；v2 后缀实现新旧栈数据并行，割接后可去除后缀 |
| 根目录 | `newiam` 为迁移期临时名，割接日旧工程归档 `iam-platform-legacy` 后改名 `iam-platform` 扶正 |

---

## 六、技术栈与中间件决策

### 注册中心引入判据（满足其一再评估引入）
1. 某服务需水平扩至多实例，且无 K8s Service / Nginx 等替代发现手段
2. 服务数 > 10 且频繁动态上下线
3. 多环境配置统一管理成为强需求（实践中本项目最先用上的会是配置中心而非服务发现）

**当前决策：不引入**。保持固定端口 + 配置直连的轻量服务化形态。

### 若引入 Nacos 的版本路线

| 路线 | 组合 | 说明 |
|---|---|---|
| 对齐（新工程推荐） | Spring Boot 升 3.5.x + SCA `2025.0.x` + Spring Cloud `2025.0.x` + Nacos Server `3.2.3` | 官方矩阵正配；Nacos 3.x 全面 Raft(CP)+gRPC，注意放行 9848 端口，服务端要求 Java 17 |
| 保守 | 留 Spring Boot 3.4.x + SCA `2023.0.3.x` + Spring Cloud `2023.0.x` + Nacos Server `2.5.3` | 非官方适配矩阵（SCA 无 Boot 3.4 官方分支），社区实跑较多，升级 Boot 时需回归 |

> SCA 官方分支对应关系：2023.x→Boot 3.2.x；2025.0.x→Boot 3.5.x；2025.1.x→Boot 4.0.x。无 Boot 3.4 官方分支。
