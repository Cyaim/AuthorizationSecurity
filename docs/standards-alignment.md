# 标准对齐说明

> 面包屑：[文档中心](README.md) / 标准与对标

Cyaim.Authentication 2.0 的设计与实现对齐以下公开标准与行业规范。本文逐项说明对齐点与实现位置。

## 访问控制模型

### NIST RBAC（INCITS 359）

| RBAC 级别 | 要求 | 实现 |
|---|---|---|
| RBAC0 核心 | 用户—角色—权限三元关系 | `AuthUser.Roles` → `AuthRole.Permissions` → 权限代码，`PermissionEvaluator` 合并求值 |
| RBAC1 层级 | 角色继承 | `AuthRole.ParentRoles`，评估时 BFS 展开（环安全），子角色继承父角色的允许与拒绝授权 |
| RBAC2 约束 | 职责分离 | 通过拒绝授权（`DeniedPermissions`，拒绝优先）实现互斥控制 |
| 会话 | 用户激活的权限子集 | 令牌作用域（scope）+ 令牌内 `perm` 声明构成会话级权限视图 |

### ABAC（NIST SP 800-162）

命名策略 `IAuthPolicy` 基于 `AuthorizationContext`（主体属性、资源属性 `Items`、环境属性 `Now`、宿主上下文）求值，可与权限代码组合（`[RequirePermission("sys.doc.edit", Policy = "owner-only")]`）。策略异常按拒绝处理（fail-closed）。

### 权限代码模型（Apache Shiro 风格分层权限字符串）

- 分层：`sys.user.read`，`.` 与 `:` 等价，不区分大小写
- 通配符：`*` 匹配恰好一段；`**` 匹配零或多段（仅末段）
- **拒绝优先（Deny-Override）**：同一代码同时命中允许与拒绝时结果为拒绝——与 XACML 的 deny-overrides 组合算法语义一致

## OAuth 2.0 / OIDC 协议族

| 标准 | 内容 | 实现位置 |
|---|---|---|
| RFC 6749 | OAuth 2.0 核心：授权码、客户端凭据、密码、刷新令牌四种授权 | `Cyaim.Authentication.Server` `/connect/token`、`/connect/authorize` |
| RFC 6750 | Bearer 令牌用法：`Authorization: Bearer`、`access_token` 查询参数、401 `WWW-Authenticate` 应答 | `CyaimAuthMiddleware` |
| RFC 7636 | PKCE（仅 S256），公共客户端强制 | `/connect/authorize` + `/connect/token` 授权码兑换 |
| RFC 7662 | 令牌自省 | `/connect/introspect` |
| RFC 7009 | 令牌吊销 | `/connect/revocation` |
| RFC 7519 | JWT：iss/aud/sub/exp/nbf/iat/jti 注册声明 | `JwtTokenService` |
| RFC 9068 §2.2.3 | `scope` 为空格分隔字符串声明 | `JwtTokenService` |
| RFC 9700（OAuth 2.0 Security BCP） | 刷新令牌轮换 + 重放检测吊销令牌家族；授权码一次性使用；redirect_uri 精确匹配 | `RefreshTokenManager`、`ITokenStore.ConsumeAuthorizationCodeAsync` |
| OIDC Discovery | `/.well-known/openid-configuration` 发现文档 | `Cyaim.Authentication.Server` |
| RFC 7517 | JWKS 公钥集 | `/.well-known/jwks`，`ITokenService.GetJwksJson()` |
| OIDC UserInfo | 用户信息端点 | `/connect/userinfo` |

## 凭据安全

| 规范 | 内容 | 实现 |
|---|---|---|
| NIST SP 800-132 | PBKDF2 口令哈希（随机盐、可升级迭代次数、参数自描述格式） | `Pbkdf2PasswordHasher`（PBKDF2-HMAC-SHA256，默认 100,000 次迭代） |
| NIST SP 800-63B | 登录失败锁定 | `UserCredentialService`（阈值 + 锁定时长可配） |
| — | 时序侧信道防护 | 口令/签名比较均使用常量时间比较 |
| — | 不透明令牌不落明文 | 刷新令牌与授权码仅存 SHA-256 哈希 |

## 可观测性

- 结构化日志：`ILogger` + `EventId`（`AuthLogEvents`，2001–2302）
- 指标：`System.Diagnostics.Metrics`，Meter `Cyaim.Authentication`（检查数/拒绝数/缓存命中/耗时直方图/令牌签发数），可接 OpenTelemetry 与 dotnet-counters
- 审计：`IAuditLogger`（登录、令牌签发/吊销、权限拒绝、管理操作、安全事件），内存环形缓冲 + 可选 JSONL 落盘
