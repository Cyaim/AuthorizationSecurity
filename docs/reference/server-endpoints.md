# OAuth2 / OIDC 端点参考

> 授权中心（`Cyaim.Authentication.Server`）对外暴露的全部 OAuth 2.0 / OpenID Connect 端点：路径、参数、成功/错误响应与可复制的 curl 示例。

`[文档中心](../README.md) / 参考`

本页描述由 `app.MapCyaimAuthServer()` 注册的端点。所有路径均为默认值，定义于 `AuthConstants.Endpoints`（源码：`src/Cyaim.Authentication.Abstractions/AuthConstants.cs`）。端点注册见 `src/Cyaim.Authentication.Server/CyaimAuthServerEndpointRouteBuilderExtensions.cs`，各端点实现位于 `src/Cyaim.Authentication.Server/Endpoints/`。

除 `GET|POST /connect/userinfo`（要求已认证）外，所有端点均带 `AllowGuest` 元数据以绕过权限中间件，各自在处理器内部完成客户端认证或用户认证。

本页示例统一以对外基地址 `https://auth.example.com` 为例。实际基地址由 `CyaimAuthServerOptions.PublicOrigin` 决定，未配置时取当前请求的 `scheme://host`（见 `ServerHttp.GetOrigin`）。

## 端点总览

| 方法 | 路径 | 用途 | 对应规范 |
| --- | --- | --- | --- |
| GET | `/.well-known/openid-configuration` | OIDC 发现文档 | OpenID Connect Discovery 1.0 |
| GET | `/.well-known/jwks` | 签名公钥集（JWKS） | RFC 7517 |
| POST | `/connect/token` | 令牌端点（四种授权） | RFC 6749 §3.2 |
| GET | `/connect/authorize` | 授权端点（授权码 + PKCE） | RFC 6749 §4.1、RFC 7636 |
| GET / POST | `/account/login` | 登录页 / 提交登录 | 非规范（SSO 会话建立） |
| GET / POST | `/account/logout` | 登出 | 非规范 |
| GET / POST | `/connect/endsession` | OIDC 结束会话 | OIDC RP-Initiated Logout |
| POST | `/connect/introspect` | 令牌自省 | RFC 7662 |
| POST | `/connect/revocation` | 令牌吊销 | RFC 7009 |
| GET / POST | `/connect/userinfo` | 用户信息 | OIDC UserInfo |

授权类型、作用域是否可用取决于 `CyaimAuthServerOptions`（`EnableAuthorizationCode`、`EnablePasswordGrant`、`EnableClientCredentials`、`EnableRefreshTokens`）。配置项完整列表见 [configuration.md](configuration.md)。

---

## GET /.well-known/openid-configuration

**用途**：OIDC 发现文档，客户端据此自动定位各端点。`Cyaim.Authentication.Client` 的 `DiscoverAsync` 即读取本文档。

**请求参数**：无。

**成功响应**（`200 OK`，`application/json`）。字段随服务器启用的授权类型动态生成（`grant_types_supported`）：

```json
{
  "issuer": "cyaim-auth",
  "authorization_endpoint": "https://auth.example.com/connect/authorize",
  "token_endpoint": "https://auth.example.com/connect/token",
  "userinfo_endpoint": "https://auth.example.com/connect/userinfo",
  "introspection_endpoint": "https://auth.example.com/connect/introspect",
  "revocation_endpoint": "https://auth.example.com/connect/revocation",
  "end_session_endpoint": "https://auth.example.com/connect/endsession",
  "jwks_uri": "https://auth.example.com/.well-known/jwks",
  "grant_types_supported": ["authorization_code", "client_credentials", "password", "refresh_token"],
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "offline_access", "permissions"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

> `issuer` 取自 `ITokenService.Issuer`（即 `CyaimAuthCoreOptions.Issuer`，默认 `cyaim-auth`）。

```bash
curl https://auth.example.com/.well-known/openid-configuration
```

---

## GET /.well-known/jwks

**用途**：返回 JSON Web Key Set，资源服务器用其验签 JWT 访问令牌。

**请求参数**：无。

**成功响应**（`200 OK`，`application/json`）：内容为 `ITokenService.GetJwksJson()` 的输出（RSA 签名时包含公钥；HMAC 签名时不含可分发公钥）。

```bash
curl https://auth.example.com/.well-known/jwks
```

---

## POST /connect/token

**用途**：签发访问令牌（并按条件签发刷新令牌）。支持 `client_credentials`、`password`、`refresh_token`、`authorization_code` 四种授权。

**内容类型**：`application/x-www-form-urlencoded`（非表单请求返回 `invalid_request`）。

**客户端认证**（RFC 6749 §2.3.1，见 `ClientAuthenticator.cs`）：
- `client_secret_basic`：`Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))`。
- `client_secret_post`：表单字段 `client_id` / `client_secret`。
- 公共客户端（存储中无 `ClientSecretHash`）仅需 `client_id`；机密客户端必须通过密钥校验。

**成功响应**（`200 OK`，含 `Cache-Control: no-store` 与 `Pragma: no-cache`）：

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "permissions offline_access",
  "refresh_token": "8f3c..."
}
```

字段说明（见 `TokenEndpoint.IssueAndRespondAsync`）：
- `scope` 仅在请求包含作用域时出现。
- `refresh_token` 仅在满足「服务器启用刷新令牌 + 客户端 `AllowOfflineAccess` + 请求作用域含 `offline_access`」时出现（`client_credentials` 不签发刷新令牌）。

**通用错误响应**（`application/json`，均带 `no-store`）：

| HTTP | error | 触发场景 |
| --- | --- | --- |
| 400 | `invalid_request` | 非表单请求；缺少 `grant_type` |
| 400 | `unsupported_grant_type` | 该授权类型未在服务器启用 |
| 400 | `unauthorized_client` | 客户端 `AllowedGrantTypes` 不含该授权类型 |
| 400 | `invalid_scope` | 请求作用域超出客户端 `AllowedScopes` |
| 400 | `invalid_grant` | 凭据/授权码/刷新令牌无效（各授权见下） |
| 401 | `invalid_client` | 客户端不存在、已禁用或密钥不匹配（附 `WWW-Authenticate: Basic`） |

错误响应体形如 `{"error":"invalid_grant","error_description":"..."}`。各错误码语义见 [decisions-and-errors.md](decisions-and-errors.md)。

### grant_type=client_credentials（RFC 6749 §4.4）

机器对机器（M2M）授权，主体即客户端本身。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `grant_type` | 是 | 固定 `client_credentials` |
| `scope` | 否 | 空格分隔，须为客户端允许作用域子集 |

```bash
curl -X POST https://auth.example.com/connect/token \
  -u demo-m2m:secret \
  -d grant_type=client_credentials \
  -d scope=permissions
```

### grant_type=password（RFC 6749 §4.3）

资源所有者密码授权。凭据由 `UserCredentialService.ValidateAsync` 校验。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `grant_type` | 是 | 固定 `password` |
| `username` | 是 | 用户名 |
| `password` | 是 | 口令 |
| `scope` | 否 | 含 `offline_access` 且客户端允许时签发刷新令牌 |

**特有错误**：缺少 `username` 或 `password` → `invalid_request`；凭据校验失败（用户不存在 / 口令错误 / 账户禁用 / 锁定）统一返回 `invalid_grant`（`error_description` 为「用户凭据无效」，不区分具体原因以防用户名枚举）。

```bash
curl -X POST https://auth.example.com/connect/token \
  -u wpf-client:secret \
  -d grant_type=password \
  -d username=alice \
  -d password=alice123 \
  -d scope="permissions offline_access"
```

### grant_type=refresh_token（RFC 6749 §6）

刷新令牌轮换：旧刷新令牌作废并换发新刷新令牌，同时按存储中最新用户数据重建主体（拿到最新角色/权限）。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `grant_type` | 是 | 固定 `refresh_token` |
| `refresh_token` | 是 | 上次签发的刷新令牌 |

**特有错误**：缺少 `refresh_token` → `invalid_request`；令牌无效/过期/已用 → `invalid_grant`；用户不存在或已禁用 → `invalid_grant`。检测到刷新令牌重放会额外记录审计并拒绝。

```bash
curl -X POST https://auth.example.com/connect/token \
  -u wpf-client:secret \
  -d grant_type=refresh_token \
  -d refresh_token=8f3c...
```

### grant_type=authorization_code（RFC 6749 §4.1 + PKCE RFC 7636）

授权码换令牌。授权码为一次性（`ConsumeAuthorizationCodeAsync`）。

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `grant_type` | 是 | 固定 `authorization_code` |
| `code` | 是 | `/connect/authorize` 回调返回的授权码 |
| `redirect_uri` | 是 | 必须与授权请求时**精确一致** |
| `code_verifier` | 条件 | 授权请求带 `code_challenge` 时必填（PKCE S256） |

**特有错误**（均为 `invalid_grant`）：缺少 `code`（`invalid_request`）；授权码无效/过期/已用；授权码不属于该客户端；`redirect_uri` 不一致；缺少 `code_verifier`；PKCE 校验失败（仅支持 `S256`）；用户不存在或已禁用。

```bash
curl -X POST https://auth.example.com/connect/token \
  -d grant_type=authorization_code \
  -d client_id=wasm-client \
  -d code=abc123 \
  -d redirect_uri=https://app.example.com/callback \
  -d code_verifier=dBjftJeZ4CVP...
```

> 生成 `code_verifier` / `code_challenge` 可用客户端 SDK 的 `Pkce.CreateCodeVerifier()` / `Pkce.CreateCodeChallenge(v)`，见 [desktop-wasm-clients.md](../guides/desktop-wasm-clients.md)。

---

## GET /connect/authorize

**用途**：授权码流程的入口。校验客户端与回调地址后，无 SSO 会话则 302 跳转登录页；有会话则签发一次性授权码并 302 回调。

**请求参数**（查询字符串）：

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `client_id` | 是 | 客户端标识 |
| `redirect_uri` | 是 | 必须已在客户端 `RedirectUris` 注册（精确匹配） |
| `response_type` | 是 | 仅支持 `code` |
| `scope` | 否 | 空格分隔，须为客户端允许作用域子集 |
| `state` | 否 | 原样回传，用于 CSRF 防护 |
| `code_challenge` | 条件 | 客户端 `RequirePkce` 为真时必填 |
| `code_challenge_method` | 条件 | 提供 `code_challenge` 时必须为 `S256` |
| `nonce` | 否 | 记录于授权码，供后续使用 |

**成功**：302 重定向到 `redirect_uri`，附加 `code`（及原样 `state`）：

```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=abc123&state=xyz
```

**错误处理分两类**（见 `AuthorizeEndpoint.cs`）：

- 客户端/回调地址校验失败时**不重定向**，直接返回 `400`（`text/plain`）：缺少 `client_id`；`client_id` 无效/禁用/未被允许授权码模式；`redirect_uri` 缺失或未注册。
- 通过上述校验后的错误经 302 回传至 `redirect_uri`（RFC 6749 §4.1.2.1），携带 `error` 与 `error_description`（及 `state`）：

| error | 触发场景 |
| --- | --- |
| `unauthorized_client` | 授权码模式未启用 |
| `unsupported_response_type` | `response_type` 非 `code` |
| `invalid_scope` | 作用域超出允许范围 |
| `invalid_request` | 要求 PKCE 但缺 `code_challenge`；`code_challenge_method` 非 `S256` |

```bash
# 浏览器地址栏访问（示例）
https://auth.example.com/connect/authorize?client_id=wasm-client&response_type=code&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20permissions%20offline_access&state=xyz&code_challenge=E9Melh...&code_challenge_method=S256
```

---

## GET /account/login

**用途**：返回内嵌的 HTML 登录页。

**请求参数**（查询字符串）：`returnUrl`（登录成功后跳转地址）、`err=1`（显示错误提示）。

**成功响应**：`200 OK`，`text/html`。

```bash
curl "https://auth.example.com/account/login?returnUrl=%2F"
```

## POST /account/login

**用途**：校验用户凭据，成功则签发 SSO 会话 Cookie（默认 `cyaim_sso`）并跳转 `returnUrl`。

**内容类型**：`application/x-www-form-urlencoded`。

**表单字段**：`username`、`password`、`returnUrl`。

**CSRF 防护**：登录 POST 校验 `Origin`/`Referer` 属于本站，跨站提交返回 `400`（`跨站请求被拒绝`，见 `ServerHttp.IsSameOriginRequest`）。

**结果**：
- 成功：`302` 重定向到 `returnUrl`（经 `IsSafeReturnUrl` 防开放重定向，非法则跳 `/`）。
- 失败：`302` 重定向回 `LoginPath?err=1`（保留 `returnUrl`）。失败原因由 `UserCredentialService` 写入审计。

```bash
curl -X POST https://auth.example.com/account/login \
  -H "Origin: https://auth.example.com" \
  -d username=admin \
  -d password=Admin!123 \
  -d returnUrl=/ -i
```

---

## GET|POST /account/logout 与 GET|POST /connect/endsession

**用途**：清除 SSO 会话 Cookie；两端点共用同一处理器（`AccountEndpoints.HandleLogoutAsync`）。

**请求参数**：`post_logout_redirect_uri`（查询字符串或表单）。

**结果**：
- 若 `post_logout_redirect_uri` 精确匹配任一**启用**客户端注册的 `PostLogoutRedirectUris`，则 `302` 跳转该地址。
- 否则返回 `200 OK`「已登出」HTML 页面。

登出会记录审计（`Category=Logout`）。

```bash
curl "https://auth.example.com/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2F" -i
```

---

## POST /connect/introspect

**用途**：令牌自省（RFC 7662）。先按访问令牌（JWT）校验，不匹配再按刷新令牌哈希查存储；都不匹配返回 `{active:false}`。

**内容类型**：`application/x-www-form-urlencoded`。

**客户端认证**：与令牌端点相同（Basic 或表单）。认证失败返回 `invalid_client`（401）。

**表单字段**：`token`（必填；缺失返回 `invalid_request`，400）。

**成功响应**（`200 OK`）——有效访问令牌：

```json
{
  "active": true,
  "sub": "u_1001",
  "token_type": "Bearer",
  "iss": "cyaim-auth",
  "client_id": "wpf-client",
  "scope": "permissions offline_access",
  "exp": 1752710400,
  "username": "alice"
}
```

字段说明（见 `IntrospectionEndpoint.cs`）：`sub`、`token_type`、`iss` 恒有；`client_id`、`scope`、`exp`、`username` 按令牌内容存在时才输出。

有效刷新令牌时返回 `active`、`sub`、`client_id`、`exp`、`scope`（无 `token_type`/`iss`/`username`）。

无效/过期/未知令牌返回（仍为 `200`，RFC 7662 §2.2）：

```json
{ "active": false }
```

```bash
curl -X POST https://auth.example.com/connect/introspect \
  -u demo-m2m:secret \
  -d token=eyJhbGciOi...
```

---

## POST /connect/revocation

**用途**：令牌吊销（RFC 7009）。刷新令牌会吊销整个令牌家族（仅限持有该令牌的客户端）；访问令牌无状态，直接返回 `200`。

**内容类型**：`application/x-www-form-urlencoded`。

**客户端认证**：与令牌端点相同。认证失败返回 `invalid_client`。

**表单字段**：`token`（必填；缺失返回 `invalid_request`）、`token_type_hint`（可选，仅作提示）。

**成功响应**：`200 OK`（无响应体）。按 RFC 7009 §2.2，无论令牌是否存在均返回 `200`。仅当刷新令牌存在且属于该客户端时才实际吊销其家族并记录审计。

```bash
curl -X POST https://auth.example.com/connect/revocation \
  -u wpf-client:secret \
  -d token=8f3c... \
  -d token_type_hint=refresh_token -i
```

---

## GET|POST /connect/userinfo

**用途**：OIDC UserInfo。返回当前主体的身份与权限。这是唯一**要求已认证**的服务器端点（映射时带 `RequirePermission()` 无参元数据 = 仅要求已认证），主体由权限中间件解析。

**认证**：`Authorization: Bearer <access_token>`（也支持 `?access_token=` 查询，取决于 `CyaimAuthOptions.AllowTokenFromQuery`，默认开启）。未认证由中间件返回 `401`。

**成功响应**（`200 OK`）：

```json
{
  "sub": "u_1001",
  "role": ["user"],
  "permissions": ["orders.read", "orders.create"],
  "scope": "permissions offline_access",
  "name": "Alice",
  "preferred_username": "alice",
  "email": "alice@example.com"
}
```

字段说明（见 `UserInfoEndpoint.cs`）：`sub`、`role`、`permissions`、`scope` 恒有；`name`、`preferred_username`、`email` 仅在主体含相应信息时输出。`permissions` 为权限评估器算出的允许集（`CompiledPermissionSet.Allows`）。

```bash
curl https://auth.example.com/connect/userinfo \
  -H "Authorization: Bearer eyJhbGciOi..."
```

---

## 相关文档

- [decisions-and-errors.md](decisions-and-errors.md) — 判断原因与错误码参考
- [configuration.md](configuration.md) — 配置项参考（`CyaimAuthServerOptions` 等）
- [auth-server-sso.md](../guides/auth-server-sso.md) — 搭建授权中心与统一登录
- [admin-api.md](admin-api.md) — 管理 REST API 参考
- [tokens-and-sessions.md](../concepts/tokens-and-sessions.md) — 令牌与会话
- [permission-codes.md](permission-codes.md) — 权限代码语法参考
- [standards-alignment.md](../standards-alignment.md) — 标准对齐说明
