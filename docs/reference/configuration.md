# 配置参考

> 五个配置类的每一个选项、默认值与说明。面包屑：[文档中心](../README.md) / 参考

Cyaim.Authentication 的配置集中在五个 options 类。ASP.NET Core 集成的 `CyaimAuthOptions` **继承** 核心 `CyaimAuthCoreOptions`——在 `AddCyaimAuthentication(o => ...)` 里一处即可配置两者的全部字段。

| 配置类 | 归属包 | 何时用 |
|---|---|---|
| `CyaimAuthCoreOptions` | Core | 仅用核心引擎（无 ASP.NET Core）时 |
| `CyaimAuthOptions` : `CyaimAuthCoreOptions` | Cyaim.Authentication | `AddCyaimAuthentication(o => ...)`，最常用 |
| `CyaimAuthServerOptions` | Server | `AddCyaimAuthServer(o => ...)` |
| `CyaimAuthAdminOptions` | AdminPanel | `AddCyaimAuthAdminPanel(o => ...)` |
| `CyaimAuthClientOptions` | Client | 构造 `CyaimAuthClient` |

---

## CyaimAuthCoreOptions（引擎与令牌）

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `Issuer` | `string` | `"cyaim-auth"` | 令牌签发者（JWT `iss`）。生产应设为稳定的逻辑标识 |
| `Audience` | `string` | `"cyaim-api"` | 令牌受众（JWT `aud`） |
| `HmacSigningKey` | `string?` | `null` | HS256 对称签名密钥，**至少 32 字节 UTF-8**。设了它用 HS256 |
| `RsaKeyFilePath` | `string?` | `null` | RS256 密钥持久化路径。`HmacSigningKey` 与本项都未设时，自动生成并持久化 2048 位 RSA 开发密钥 |
| `DefaultAccessTokenLifetime` | `TimeSpan` | 1 小时 | 访问令牌默认有效期（客户端可覆盖） |
| `DefaultRefreshTokenLifetime` | `TimeSpan` | 14 天 | 刷新令牌默认有效期 |
| `ClockSkew` | `TimeSpan` | 30 秒 | 校验令牌有效期时的时钟偏移容忍 |
| `GuestRoles` | `List<string>` | 空 | 游客（未认证）主体拥有的角色 |
| `PermissionCacheTtl` | `TimeSpan` | 5 分钟 | 编译权限集缓存 TTL（版本失效之外的兜底） |
| `MaxCachedPermissionSets` | `int` | `10000` | 权限集缓存最大主体数，超出后整体清空重建 |
| `IncludePermissionsInToken` | `bool` | `true` | 是否把主体有效权限写入令牌 `perm` 声明（离线判断用） |
| `AuditCapacity` | `int` | `5000` | 审计事件内存保留条数 |
| `AuditFilePath` | `string?` | `null` | 审计 JSONL 落盘路径（空则不落盘） |
| `MaxAccessFailedCount` | `int` | `5` | 登录失败锁定阈值 |
| `LockoutDuration` | `TimeSpan` | 5 分钟 | 锁定时长 |

---

## CyaimAuthOptions（ASP.NET Core 集成，继承上表全部字段）

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `AuthorizationHeaderName` | `string` | `"Authorization"` | 凭据请求头名称（Bearer 方案） |
| `AllowTokenFromQuery` | `bool` | `true` | 允许从查询字符串取令牌（WebSocket 握手常用）。⚠️ 令牌进 URL 会被访问日志记录，见[生产清单](../guides/production-checklist.md) |
| `QueryTokenParameter` | `string` | `"access_token"` | 查询字符串令牌参数名 |
| `AllowTokenFromCookie` | `bool` | `false` | 允许从 Cookie 取令牌 |
| `CookieTokenName` | `string` | `"cyaim_token"` | Cookie 令牌名 |
| `ProtectAllEndpoints` | `bool` | `false` | true 时未标注的端点也要求已认证（`[AllowGuest]`/`[AllowAnonymous]` 放行） |
| `AuditDenials` | `bool` | `true` | 拒绝请求写审计日志 |
| `ScanEndpointPermissions` | `bool` | `true` | 启动时扫描端点权限并登记到权限定义存储 |
| `OnDenied` | `Func<HttpContext, AuthorizationDecision?, Task>?` | `null` | 自定义拒绝响应（设置后替代默认 JSON 响应） |

---

## CyaimAuthServerOptions（授权服务器）

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `PublicOrigin` | `string?` | `null` | 发现文档中各端点 URL 的基地址；空则取当前请求 `scheme://host` |
| `EnablePasswordGrant` | `bool` | `true` | 启用 `password` 授权 |
| `EnableClientCredentials` | `bool` | `true` | 启用 `client_credentials` 授权 |
| `EnableAuthorizationCode` | `bool` | `true` | 启用 `authorization_code`（含 PKCE）授权 |
| `EnableRefreshTokens` | `bool` | `true` | 启用 `refresh_token` 授权 |
| `SsoCookieName` | `string` | `"cyaim_sso"` | SSO 会话 Cookie 名 |
| `SsoSessionLifetime` | `TimeSpan` | 8 小时 | SSO 会话有效期上限 |
| `LoginPath` | `string` | `"/account/login"` | 登录页路径 |
| `ServerName` | `string` | `"Cyaim Auth"` | 登录页标题等展示名 |
| `SsoCookieSecurePolicy` | `CookieSecurePolicy` | `SameAsRequest` | SSO Cookie 的 Secure 策略。反代终止 TLS 时应设 `Always`，见[生产清单](../guides/production-checklist.md) |

---

## CyaimAuthAdminOptions（管理面板）

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `BasePath` | `string` | `"/auth-admin"` | 面板挂载基路径（SPA 与 `/api` 都在其下） |
| `TokenEndpoint` | `string` | `"/connect/token"` | SPA 密码登录用的令牌端点 |
| `ClientId` | `string` | `"cyaim-admin-panel"` | SPA 登录用的客户端 Id（需在客户端存储中注册） |
| `ServerName` | `string?` | `null` | 面板展示名 |

---

## CyaimAuthClientOptions（客户端 SDK）

| 选项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `Authority` | `string` | `""` | 授权服务器基地址（必填），如 `https://auth.example.com` |
| `ClientId` | `string` | `""` | 客户端 Id |
| `ClientSecret` | `string?` | `null` | 客户端密钥（机密客户端） |
| `Scopes` | `List<string>` | `["permissions","offline_access"]` | 申请的作用域 |
| `AutoRefresh` | `bool` | `true` | 访问令牌将过期时自动用刷新令牌续期 |
| `RefreshSkew` | `TimeSpan` | 60 秒 | 提前多久视为需要刷新 |
| `DiscoveryPath` | `string` | `"/.well-known/openid-configuration"` | 发现文档路径（相对 `Authority`） |

---

## 相关文档

- [快速上手](../getting-started.md)
- [生产部署清单](../guides/production-checklist.md)
- [公开 API 参考](api.md)
- [权限代码语法](permission-codes.md)
