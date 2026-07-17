# 判断原因与错误码参考

> 汇总权限判断原因（`AuthorizationReason`）、中间件拒绝响应体、OAuth 错误码、管理 API 错误语义与凭据校验失败码，供人与工具排查「为什么被拒绝」。

`[文档中心](../README.md) / 参考`

本页覆盖四类结果来源：
1. **权限中间件**（`src/Cyaim.Authentication/AspNetCore/CyaimAuthMiddleware.cs`）——保护业务端点的 401/403。
2. **令牌端点**（`src/Cyaim.Authentication.Server/Endpoints/`）——OAuth 2.0 错误码。
3. **管理 REST API**（`src/Cyaim.Authentication.AdminPanel/AdminApi/AdminApiEndpoints.cs`）——400/403/404/409。
4. **凭据校验**（`src/Cyaim.Authentication.Core/Security/UserCredentialService.cs`）——登录/密码授权失败码。

---

## 一、权限判断原因 AuthorizationReason

`AuthorizationReason` 枚举（`src/Cyaim.Authentication.Abstractions/Authorization/AuthorizationDecision.cs`）是每个 `AuthorizationDecision` 携带的可诊断原因。`HttpContext.CheckPermissionAsync(code)` 返回的 `AuthorizationDecision.Reason` 即取此枚举。

值 0–3 表示**放行**（`IsGranted = true`），10 及以上表示**拒绝**。

| 值 | 名称 | 含义 | 放行/拒绝 |
| --- | --- | --- | --- |
| 0 | `Granted` | 命中允许规则 | 放行 |
| 1 | `GrantedByPolicy` | ABAC 策略评估通过 | 放行 |
| 2 | `NotProtected` | 端点未要求权限 | 放行 |
| 3 | `GuestAllowed` | 允许游客访问 | 放行 |
| 10 | `NoMatchingGrant` | 未命中任何授权规则（无 allow 也无 deny） | 拒绝 |
| 11 | `DeniedByRule` | 命中拒绝规则（deny 优先） | 拒绝 |
| 12 | `GuestNotAllowed` | 未认证且端点不允许游客 | 拒绝 |
| 13 | `SubjectDisabled` | 主体被禁用或锁定（含安全戳失配） | 拒绝 |
| 14 | `PolicyNotSatisfied` | ABAC 策略评估未通过 | 拒绝 |
| 15 | `PolicyNotFound` | 引用的策略不存在 | 拒绝 |
| 16 | `InvalidPermissionCode` | 端点声明的权限代码非法 | 拒绝 |
| 17 | `InvalidCredential` | 凭据无效或过期 | 拒绝 |

关于拒绝优先（deny-override）与代码匹配规则，见 [permission-codes.md](permission-codes.md)。

---

## 二、中间件拒绝响应（401 / 403）

权限中间件对**受保护端点**（带 `RequirePermission` 等元数据）的请求判断失败时，写标准 JSON 响应体。HTTP 状态由**认证状态**决定，与具体 `AuthorizationReason` 无关：

- **未认证**（无令牌或令牌无效）→ `401 Unauthorized`
- **已认证但权限不足** → `403 Forbidden`

### 响应体结构

无论 401 还是 403，响应体一致（`application/json`，见 `CyaimAuthMiddleware.DenyAsync`）：

```json
{
  "error": "forbidden",
  "error_description": "NoMatchingGrant",
  "permission": "orders.delete"
}
```

| 字段 | 说明 |
| --- | --- |
| `error` | 结果类别：`unauthorized` / `invalid_token`（401）或 `forbidden`（403） |
| `error_description` | `AuthorizationReason` 的字符串形式（如 `NoMatchingGrant`、`DeniedByRule`、`SubjectDisabled`） |
| `permission` | 触发拒绝的权限代码；无具体代码时为 `null` |

> 可通过 `CyaimAuthOptions.OnDenied` 委托自定义拒绝响应，设置后框架不再写入上述默认响应体。

### error 取值与 WWW-Authenticate

| HTTP | `error` | 触发条件 | `WWW-Authenticate` 头 |
| --- | --- | --- | --- |
| 401 | `unauthorized` | 请求未携带令牌（游客），且端点不允许游客 | `Bearer` |
| 401 | `invalid_token` | 携带的令牌无效/过期（`TokenState.Invalid`） | `Bearer error="invalid_token"`（RFC 6750 §3） |
| 403 | `forbidden` | 已认证主体权限不足 | 无 |

### 原因到状态码的实际映射

由于状态由认证状态决定，同一 `AuthorizationReason` 在不同认证状态下可能对应不同 HTTP：

| Reason | 未认证主体 | 已认证主体 |
| --- | --- | --- |
| `GuestNotAllowed` | 401 | —（该原因仅在未认证时产生） |
| `NoMatchingGrant` | 401 | 403 |
| `DeniedByRule` | 401 | 403 |
| `InvalidPermissionCode` | 401 | 403 |
| `PolicyNotSatisfied` / `PolicyNotFound` | 401 | 403 |
| `SubjectDisabled` | — | 403（账户禁用/锁定/安全戳失配） |

> `SubjectDisabled` 用于已认证但账户在令牌签发后被禁用/锁定，或口令重置导致安全戳不一致的情况——即便令牌本身尚未过期也会被拒绝。

---

## 三、OAuth 2.0 错误码（令牌与授权端点）

令牌端点（`/connect/token`）以 RFC 6749 §5.2 格式返回错误：

```json
{ "error": "invalid_grant", "error_description": "用户凭据无效" }
```

所有错误响应带 `Cache-Control: no-store` 与 `Pragma: no-cache`。

| error | HTTP | 触发场景 |
| --- | --- | --- |
| `invalid_request` | 400 | 非 `x-www-form-urlencoded` 请求；缺 `grant_type`；缺 `username`/`password`（password）；缺 `refresh_token`；缺 `code`；Basic 认证头格式错误 |
| `invalid_client` | 401 | 客户端不存在、已禁用、缺凭据或密钥不匹配（附 `WWW-Authenticate: Basic`） |
| `invalid_grant` | 400 | 用户凭据无效（password）；刷新令牌无效/过期/已用/重放；授权码无效/过期/已用/不属于该客户端；`redirect_uri` 不一致；缺 `code_verifier` 或 PKCE 校验失败；用户不存在或已禁用 |
| `unauthorized_client` | 400 | 客户端 `AllowedGrantTypes` 不含该授权类型；（授权端点）授权码模式未启用 |
| `unsupported_grant_type` | 400 | 请求的授权类型未在服务器启用 |
| `invalid_scope` | 400 | 请求作用域超出客户端 `AllowedScopes` |

**授权端点（`/connect/authorize`）补充**：`client_id`/`redirect_uri` 校验失败时**不重定向**，直接返回 `400 text/plain`；通过校验后的错误经 302 回调携带 `error`、`error_description`（及 `state`），可能取值：`unauthorized_client`、`unsupported_response_type`、`invalid_scope`、`invalid_request`。详见 [server-endpoints.md](server-endpoints.md)。

> 安全设计：password 授权对「用户不存在 / 口令错误 / 账户禁用 / 锁定」统一返回 `invalid_grant`，不区分具体原因，避免用户名枚举与账户状态探测。

---

## 四、管理 REST API 错误语义（4xx）

管理 API（前缀 `{BasePath}/api`，默认 `/auth-admin/api`）统一以 `{"error": "<消息>"}`（camelCase JSON）返回错误。除权限中间件产生的 401/403 外，处理器内部产生以下状态：

| HTTP | 语义 | 典型场景 |
| --- | --- | --- |
| 400 | 请求校验失败 | 必填项缺失（如 `userName`/`password`、`clientId`、角色 `name`）；请求体非 JSON；权限代码无法规范化（`非法权限代码 "..."`）；存储层 `InvalidOperationException`（更新/删除约束，如系统内置角色不可删） |
| 403 | 职责分离守卫 | 授予/修改角色、权限或客户端权限时，调用者本身缺少对应 `Manage*` 权限（`RequireManageAsync`，如「该操作涉及授予权限或角色，需要 auth.admin.permissions 权限」） |
| 404 | 目标不存在 | 按 `id`/`code` 未找到用户、角色、权限、客户端 |
| 409 | 唯一性冲突 | 创建用户/角色/客户端时标识重复（`CreateAsync` 抛 `InvalidOperationException`） |

**职责分离要点**（防纵向越权，见源码注释）：
- 创建/更新用户时若涉及 `Roles` → 需 `auth.admin.roles`；涉及 `DirectPermissions`/`DeniedPermissions` → 需 `auth.admin.permissions`。
- 创建/更新角色时若涉及 `Permissions`/`DeniedPermissions` → 需 `auth.admin.permissions`。
- 创建/更新客户端时若涉及 `Permissions` → 需 `auth.admin.permissions`。

各端点所需权限见 [admin-api.md](admin-api.md)。管理权限代码见 `AuthConstants.AdminPermissions`（`auth.admin.**` / `auth.admin.read` / `auth.admin.users` / `auth.admin.roles` / `auth.admin.permissions` / `auth.admin.clients` / `auth.admin.audit`）。

---

## 五、凭据校验失败码

`UserCredentialService.ValidateAsync` 返回的 `CredentialValidationResult.Error` 为以下三者之一（登录页与 password 授权共用此逻辑）：

| Error | 含义 | 备注 |
| --- | --- | --- |
| `invalid_credentials` | 用户不存在或口令错误 | 两种情形返回同一码，且对不存在用户执行等价开销的假哈希校验，抹平计时差以防用户名枚举 |
| `account_disabled` | 账户已禁用（`IsEnabled = false`） | |
| `locked_out` | 账户锁定中（`IsLockedOut`） | 连续失败达 `MaxAccessFailedCount`（默认 5）后锁定 `LockoutDuration`（默认 5 分钟） |

**对外暴露方式**：
- **password 授权**：上述三种失败对外统一映射为 OAuth `invalid_grant`（不透出具体码）。
- **登录页 POST**：失败时 `302` 回登录页并附 `err=1`；具体原因仅写入审计（`Category=Login`，`Outcome=Denied`），不回显给用户。

每次校验（成功或失败）都会写审计事件，可经管理 API `GET /audit` 查询。审计与锁定相关配置见 [configuration.md](configuration.md)。

---

## 相关文档

- [server-endpoints.md](server-endpoints.md) — OAuth2/OIDC 端点参考
- [admin-api.md](admin-api.md) — 管理 REST API 参考
- [permission-codes.md](permission-codes.md) — 权限代码语法参考
- [permission-model.md](../concepts/permission-model.md) — 权限模型（allow/deny、角色继承）
- [configuration.md](configuration.md) — 配置项参考
- [protect-aspnetcore.md](../guides/protect-aspnetcore.md) — 保护 ASP.NET Core API
