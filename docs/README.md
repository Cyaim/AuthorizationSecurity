# Cyaim.Authentication 文档中心

> Cyaim.Authentication 2.0 的统一文档入口。所有文档都从这里索引——不散落。面向开发者与 LLM 阅读。

Cyaim.Authentication 是一个 .NET 权限框架：**RBAC/ABAC 授权引擎 + OAuth 2.0 / OIDC 兼容授权服务器 + 统一登录（SSO）+ 内嵌权限管理面板 + 跨平台客户端 SDK**。

- 项目介绍与 30 秒上手：[根 README](../README.md)
- 交付验证报告（构建/测试/基准/评审证据）：[VERIFICATION.md](../VERIFICATION.md)
- LLM 索引文件：[llms.txt](../llms.txt)

---

## 按角色选择阅读路径

| 你是… | 建议阅读顺序 |
|---|---|
| **第一次接触** | [快速上手](getting-started.md) → [架构总览](concepts/architecture.md) → [权限模型](concepts/permission-model.md) |
| **给现有 API 加权限** | [保护 ASP.NET Core API](guides/protect-aspnetcore.md) → [权限代码语法](reference/permission-codes.md) → [配置参考](reference/configuration.md) |
| **搭建统一登录/授权中心** | [搭建授权中心与 SSO](guides/auth-server-sso.md) → [令牌与会话](concepts/tokens-and-sessions.md) → [服务器端点参考](reference/server-endpoints.md) |
| **做管理后台** | [使用管理面板](guides/admin-panel.md) → [管理 API 参考](reference/admin-api.md) |
| **写桌面/浏览器客户端** | [桌面/WASM/控制台客户端](guides/desktop-wasm-clients.md) → [示例总览](samples.md) |
| **接数据库存储 / 自定义策略** | [自定义存储](guides/custom-stores.md) → [自定义 ABAC 策略](guides/custom-policies.md) |
| **多实例集群部署** | [集群部署](guides/clustering.md) → [自定义存储](guides/custom-stores.md) → [生产部署清单](guides/production-checklist.md) |
| **准备上生产** | [生产部署清单](guides/production-checklist.md) → [配置参考](reference/configuration.md) |
| **从 1.x 升级** | [从 1.x 迁移](migration-1x.md) |
| **评估技术选型** | [标准对齐](standards-alignment.md) → [对标 IdentityServer](id5-parity.md) → [性能基准](benchmark-results.md) |
| **LLM / 自动化工具** | [llms.txt](../llms.txt)（简明索引）+ 本页完整目录 |

---

## 完整目录

### 入门
- [快速上手](getting-started.md) —— 五种集成场景的最小可运行代码

### 概念（Concepts）
- [架构总览](concepts/architecture.md) —— 六个包的职责与依赖、一次请求的鉴权数据流、两种部署形态、扩展点
- [权限模型](concepts/permission-model.md) —— 权限代码语法、通配符、拒绝优先、RBAC 角色层级、ABAC 策略、权限集编译与缓存
- [令牌与会话](concepts/tokens-and-sessions.md) —— JWT 声明、HS256/RS256、JWKS、刷新令牌轮换、SSO 会话、安全戳、口令哈希

### 指南（Guides，任务导向）
- [保护 ASP.NET Core API](guides/protect-aspnetcore.md) —— 中间件、`[RequirePermission]`、Minimal API、命令式判断、`[Authorize]` 桥接
- [WebSocket 鉴权](guides/websocket.md) —— 握手鉴权与消息级细粒度判断
- [搭建授权中心与统一登录](guides/auth-server-sso.md) —— OAuth2/OIDC 端点、四种授权、SSO 单点登录、数据播种
- [使用权限管理面板](guides/admin-panel.md) —— `/auth-admin` 面板、管理权限模型、职责分离
- [桌面/WASM/控制台客户端](guides/desktop-wasm-clients.md) —— Client SDK、自动刷新、令牌缓存、UI 权限门控
- [自定义存储（EF/数据库）](guides/custom-stores.md) —— 六个存储接口、实现要点、`MapStore<T>` 与单例约束
- [自定义 ABAC 策略](guides/custom-policies.md) —— `AddPolicy`、`AuthorizationContext`、`RequireAuthPolicy`
- [集群部署（多实例）](guides/clustering.md) —— 共享数据/密钥、跨实例缓存失效、集群版本组件
- [生产部署清单](guides/production-checklist.md) —— 密钥、Cookie 安全、CORS、令牌有效期、审计、可观测性

### 参考（Reference，速查）
- [配置参考](reference/configuration.md) —— 五个配置类的每一个选项、默认值、说明
- [公开 API 参考](reference/api.md) —— 按包组织的公共类型与关键成员签名
- [权限代码语法](reference/permission-codes.md) —— 规范化、分隔符、通配符匹配规则与示例表
- [服务器端点参考](reference/server-endpoints.md) —— 每个 OAuth2/OIDC 端点的参数、响应、curl 示例、对应 RFC
- [管理 API 参考](reference/admin-api.md) —— 每个管理 REST 端点的方法、权限、请求/响应
- [判断原因与错误码](reference/decisions-and-errors.md) —— `AuthorizationReason`、HTTP 结果、OAuth 错误码

### 标准、对标与迁移
- [标准对齐](standards-alignment.md) —— NIST RBAC/ABAC、OAuth2 RFC 全家桶、OIDC、JWT、PBKDF2 的对齐点与实现位置
- [对标 IdentityServer（ID5）](id5-parity.md) —— 功能矩阵与已知差距
- [从 1.x 迁移](migration-1x.md) —— API 对照表与渐进迁移路径

### 示例与数据
- [示例总览](samples.md) —— 四个可运行示例的路径、启动命令、端口、演示账户
- [性能基准](benchmark-results.md) —— 实测数据（判断 ~20ns、比 1.x 快数千至数十万倍）
- [交付验证报告](../VERIFICATION.md) —— 构建/测试/基准/端到端/对抗评审的完整证据

---

## 核心概念速记（一屏读懂）

- **七个包**：`Abstractions`（契约+匹配引擎，零依赖）· `Core`（引擎/JWT/存储/审计）· `Cyaim.Authentication`（ASP.NET Core 集成）· `Server`（OAuth2/OIDC+SSO）· `AdminPanel`（管理面板）· `Client`（客户端 SDK）· `EntityFrameworkCore`（共享数据库存储 + 集群）
- **权限代码**：分层字符串，`.` 与 `:` 等价、大小写不敏感；`*` 匹配一段、`**` 匹配任意后代；**拒绝优先**
- **组装顺序**：`AddCyaimAuthentication(...).AddInMemoryStore()` →（可选 `AddCyaimAuthServer` / `AddCyaimAuthAdminPanel`）→ `app.UseCyaimAuthentication()` →（可选 `MapCyaimAuthServer` / `MapCyaimAuthAdmin`）
- **标注端点**：`[RequirePermission("mod.res.action")]` / `.RequirePermission("...")` / `[AllowGuest]` / 无参 `RequirePermission()` = 仅要求已认证
- **对齐标准**：NIST RBAC0-2、ABAC、OAuth2（RFC 6749/6750/7636/7662/7009/9068/9700）、OIDC、JWKS、PBKDF2

---

_本文档中心随代码演进。所有 API 名称、配置项、端点均以源码为准；参考文档由源码核对生成。_
