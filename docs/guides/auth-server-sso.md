# 搭建授权中心与统一登录

> 用 Cyaim.Authentication.Server 在几十行代码内搭起一个 OAuth 2.0 / OIDC 兼容的独立授权中心，让多个应用共享同一套账号、登录页与令牌签发。

[文档中心](../README.md) / 指南（Guides）

本篇讲“怎么把一个 ASP.NET Core 应用变成授权中心”。如果你只是想给一个已有 API 加权限校验、不需要签发令牌，请看 [保护 ASP.NET Core API](protect-aspnetcore.md)。令牌与会话的原理见 [令牌与会话](../concepts/tokens-and-sessions.md)，端点逐个字段的速查见 [服务器端点参考](../reference/server-endpoints.md)。

---

## 授权中心能做什么

一个 Cyaim 授权中心对外提供这些能力：

- **签发令牌**：`POST /connect/token` 支持四种 OAuth 2.0 授权（client_credentials、password、authorization_code+PKCE、refresh_token）。
- **统一登录（SSO）**：内置登录页 `/account/login`，登录成功后写一个 SSO 会话 Cookie；此后同一浏览器访问任意接入应用的授权码流程都无需再次登录。
- **OIDC 发现与 JWKS**：`/.well-known/openid-configuration` 与 `/.well-known/jwks`，资源服务器和客户端可自动获知端点与验签公钥。
- **令牌自省 / 吊销 / 用户信息 / 结束会话**：`/connect/introspect`、`/connect/revocation`、`/connect/userinfo`、`/connect/endsession`。

授权中心自身也是一个普通的 ASP.NET Core 应用，可以和业务代码、[管理面板](admin-panel.md) 跑在同一进程，也可以独立部署。

---

## 最小可运行的授权中心

引用两个包（授权服务器 + 可选的管理面板）：

```xml
<PackageReference Include="Cyaim.Authentication.Server" Version="2.0.0" />
<PackageReference Include="Cyaim.Authentication.AdminPanel" Version="2.0.0" />
```

组装顺序固定为：先 `AddCyaimAuthentication(...)` 注册核心引擎与存储，再 `AddCyaimAuthServer(...)`，然后中间件 `UseCyaimAuthentication()`，最后映射端点 `MapCyaimAuthServer()`。

```csharp
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Core;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";   // 令牌签发者，写进 JWT 的 iss
    o.Audience = "my-api";                    // 令牌受众，写进 JWT 的 aud
    o.HmacSigningKey = "至少32字节的共享签名密钥..........";  // HS256；留空则自动生成 RSA 密钥用 RS256
    o.AuditFilePath = "logs/audit.jsonl";     // 可选：审计落盘
}).AddJsonFileStore("data/auth-store.json");  // JSON 文件持久化；生产可换自定义存储

builder.Services.AddCyaimAuthServer(o =>
{
    o.ServerName = "示例授权中心";            // 登录页标题、发现文档展示名
});

builder.Services.AddCyaimAuthAdminPanel();    // 可选：/auth-admin 管理面板

var app = builder.Build();

app.UseCyaimAuthentication();  // 权限中间件（必须在 Map 之前）
app.MapCyaimAuthServer();      // 挂载全部 OAuth2/OIDC 端点
app.MapCyaimAuthAdmin();       // 可选：挂载管理面板

app.Run();
```

> `HmacSigningKey` 与 `Issuer` / `Audience` 是授权中心与资源服务器之间的“契约”——资源服务器用同一份密钥与签发者/受众才能验签。详见下文[资源服务器如何对接](#资源服务器如何对接)。存储可选项与自定义数据库存储见 [自定义存储](custom-stores.md)，全部配置项见 [配置参考](../reference/configuration.md)。

`MapCyaimAuthServer()` 一次性注册下列端点（源码：`src/Cyaim.Authentication.Server/CyaimAuthServerEndpointRouteBuilderExtensions.cs`）：

| 端点 | 方法 | 用途 |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC 发现文档 |
| `/.well-known/jwks` | GET | 验签公钥集（JWKS） |
| `/connect/token` | POST | 令牌端点（四种授权） |
| `/connect/authorize` | GET | 授权端点（授权码 + PKCE） |
| `/account/login` | GET / POST | 统一登录页 |
| `/account/logout` | GET / POST | 登出 |
| `/connect/endsession` | GET / POST | OIDC 结束会话 |
| `/connect/introspect` | POST | 令牌自省（RFC 7662） |
| `/connect/revocation` | POST | 令牌吊销（RFC 7009） |
| `/connect/userinfo` | GET / POST | 用户信息（唯一要求已认证的端点） |

---

## 用 AuthDataSeeder 播种初始数据

空存储启动后没有任何用户，登录不进去。用 `AuthDataSeeder` 幂等地播种角色、用户、客户端和权限定义——它对每一项都是“存在即跳过、不覆盖”，可以放心地在每次启动时运行。

`AuthDataSeeder` 已由 `AddCyaimAuthentication` 注册进容器，从作用域里取出即可（源码：`src/Cyaim.Authentication.Core/AuthDataSeeder.cs`）。

```csharp
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();

    // 1) 角色：可携带权限、父角色、显式拒绝权限
    await seeder.EnsureRoleAsync("admin",
        new[] { AuthConstants.AdminPermissions.All, "demo.**" },
        displayName: "系统管理员", isSystem: true);
    await seeder.EnsureRoleAsync("order-viewer",
        new[] { "demo.order.read" }, displayName: "订单查看");
    await seeder.EnsureRoleAsync("order-admin",
        new[] { "demo.order.**" },
        parentRoles: new[] { "order-viewer" }, displayName: "订单管理");

    // 2) 用户：口令由内置 PBKDF2 哈希器加盐哈希
    await seeder.EnsureUserAsync("admin", "Admin!123",
        roles: new[] { "admin" }, displayName: "管理员");
    await seeder.EnsureUserAsync("alice", "alice123",
        roles: new[] { "order-admin" }, displayName: "Alice");

    // 3) 客户端：不同应用形态用不同授权类型（见下）
    await seeder.EnsureClientAsync("cyaim-admin-panel", clientSecret: null,
        allowedGrantTypes: new[] { AuthConstants.GrantTypes.Password, AuthConstants.GrantTypes.RefreshToken },
        allowedScopes: new[] { AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
        allowOfflineAccess: true, clientName: "权限管理面板");

    await seeder.EnsureClientAsync("wasm-client", clientSecret: null,
        allowedGrantTypes: new[] { AuthConstants.GrantTypes.AuthorizationCode, AuthConstants.GrantTypes.RefreshToken },
        allowedScopes: new[] { AuthConstants.Scopes.OpenId, AuthConstants.Scopes.Profile, AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
        redirectUris: new[] { "http://localhost:5290/callback" },
        postLogoutRedirectUris: new[] { "http://localhost:5290/" },
        allowOfflineAccess: true, clientName: "Blazor WASM 示例", requirePkce: true);

    await seeder.EnsureClientAsync("demo-m2m", clientSecret: "m2m-secret-please-change",
        allowedGrantTypes: new[] { AuthConstants.GrantTypes.ClientCredentials },
        allowedScopes: new[] { AuthConstants.Scopes.Permissions },
        permissions: new[] { "demo.order.read" },   // 客户端凭据模式下直接授予令牌的权限
        clientName: "演示服务客户端");

    // 4) 权限定义（供管理面板下拉展示；元组为 (Code, DisplayName?, Group?)）
    await seeder.EnsurePermissionDefinitionsAsync(new (string, string?, string?)[]
    {
        ("demo.order.read", "查看订单", "订单"),
        ("demo.order.create", "创建订单", "订单"),
        ("demo.order.delete", "删除订单", "订单"),
    });
}
```

三个播种方法的完整签名（默认参数省略部分）：

```csharp
Task<AuthRole> EnsureRoleAsync(
    string name, IEnumerable<string>? permissions = null,
    IEnumerable<string>? parentRoles = null, IEnumerable<string>? deniedPermissions = null,
    string? displayName = null, bool isSystem = false, CancellationToken cancellationToken = default);

Task<AuthUser> EnsureUserAsync(
    string userName, string password, IEnumerable<string>? roles = null,
    IEnumerable<string>? directPermissions = null, string? displayName = null,
    string? email = null, CancellationToken cancellationToken = default);

Task<ClientApplication> EnsureClientAsync(
    string clientId, string? clientSecret, IEnumerable<string> allowedGrantTypes,
    IEnumerable<string>? allowedScopes = null, IEnumerable<string>? redirectUris = null,
    IEnumerable<string>? permissions = null, bool allowOfflineAccess = false,
    string? clientName = null, bool requirePkce = true,
    IEnumerable<string>? postLogoutRedirectUris = null, CancellationToken cancellationToken = default);
```

要点：

- **公共客户端（桌面 / SPA）** 传 `clientSecret: null`；**机密客户端（服务间调用）** 传密钥字符串，密钥经 PBKDF2 哈希存储。
- `EnsureClientAsync` 的 `permissions` 只对 **client_credentials** 有意义——它是直接授予“无用户”令牌的权限集；用户令牌的权限来自其角色/直接权限，由权限引擎计算，见 [权限模型](../concepts/permission-model.md)。
- 授权码客户端必须注册 `redirectUris`；授权端点会精确比对回调地址，未注册的地址一律拒绝。
- 权限代码语法（分层、`*` / `**` 通配、拒绝优先）见 [权限代码语法](../reference/permission-codes.md)。

---

## 四种授权流程

下面示例以本地授权中心 `http://127.0.0.1:5299` 为例（对应 `samples/Sample.AuthServer`）。令牌端点一律接受 `application/x-www-form-urlencoded` 表单；客户端认证可用 HTTP Basic 头或表单里的 `client_id` / `client_secret`。

### 1. client_credentials（服务间调用，无用户）

机密客户端用自己的密钥换取一个代表“应用自身”的令牌，权限来自客户端的 `permissions`。

```bash
curl -X POST http://127.0.0.1:5299/connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=demo-m2m" \
  -d "client_secret=m2m-secret-please-change" \
  -d "scope=permissions"
```

也可以用 Basic 头传客户端凭据（等价）：

```bash
curl -X POST http://127.0.0.1:5299/connect/token \
  -u "demo-m2m:m2m-secret-please-change" \
  -d "grant_type=client_credentials" \
  -d "scope=permissions"
```

成功响应（所有授权类型格式一致）：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "permissions"
}
```

### 2. password（资源所有者密码，桌面/受信客户端）

客户端直接提交用户名口令。仅建议用于第一方受信应用（如桌面客户端）。带上 `offline_access` 且客户端 `AllowOfflineAccess=true` 时才会返回 `refresh_token`。

```bash
curl -X POST http://127.0.0.1:5299/connect/token \
  -d "grant_type=password" \
  -d "client_id=wpf-client" \
  -d "username=alice" \
  -d "password=alice123" \
  -d "scope=permissions offline_access"
```

响应额外带 `refresh_token` 字段。凭据错误返回 `400 { "error": "invalid_grant" }`。

### 3. authorization_code + PKCE（浏览器 / SPA，推荐）

这是最安全、也是启用 SSO 的流程。分两步：

**第一步：浏览器跳到授权端点。** 客户端本地先生成 PKCE 校验串 `code_verifier`，再算出 `code_challenge = BASE64URL(SHA256(verifier))`（仅支持 S256）。

```http
GET /connect/authorize
  ?response_type=code
  &client_id=wasm-client
  &redirect_uri=http://localhost:5290/callback
  &scope=openid%20profile%20permissions%20offline_access
  &state=xyz
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

授权端点校验 `client_id` 与 `redirect_uri` 后：**若没有 SSO 会话**，302 跳到 `/account/login?returnUrl=...`；用户登录成功后再跳回授权端点；**已有会话**则直接签发一次性授权码并 302 回调：

```
http://localhost:5290/callback?code=<一次性授权码>&state=xyz
```

**第二步：用授权码换令牌。** `redirect_uri` 必须与第一步逐字一致，`code_verifier` 必须与 `code_challenge` 匹配。

```bash
curl -X POST http://127.0.0.1:5299/connect/token \
  -d "grant_type=authorization_code" \
  -d "client_id=wasm-client" \
  -d "code=<一次性授权码>" \
  -d "redirect_uri=http://localhost:5290/callback" \
  -d "code_verifier=<第一步的 code_verifier>"
```

授权码一次性、短时有效，重复使用返回 `invalid_grant`。客户端 SDK（`Cyaim.Authentication.Client`）内置 `Pkce` 工具与 `ExchangeAuthorizationCodeAsync`，无需手写这些拼接，见 [桌面/WASM/控制台客户端](desktop-wasm-clients.md)。

### 4. refresh_token（静默续期）

用未过期的刷新令牌换一对新令牌。刷新令牌**轮换**（每次换新，旧的作废）并检测重放；换发时会按存储中的最新用户数据重建主体，因此角色/权限变更会在续期后生效。

```bash
curl -X POST http://127.0.0.1:5299/connect/token \
  -d "grant_type=refresh_token" \
  -d "client_id=wpf-client" \
  -d "refresh_token=<上一次拿到的 refresh_token>"
```

> 是否签发刷新令牌由三个条件同时决定：服务器 `EnableRefreshTokens=true`、客户端 `AllowOfflineAccess=true`、且本次请求 `scope` 含 `offline_access`。

各授权类型可通过 `CyaimAuthServerOptions` 上的 `EnablePasswordGrant` / `EnableClientCredentials` / `EnableAuthorizationCode` / `EnableRefreshTokens` 单独开关（默认全开）。

---

## SSO 统一登录：多应用共享一次登录

“统一登录”靠的是 **授权码流程 + 共享的 SSO 会话 Cookie**：

1. 用户在应用 A 里点登录 → 浏览器跳到授权中心 `/connect/authorize`。
2. 授权中心发现没有 SSO 会话 → 跳到 `/account/login`；用户输入一次账号口令。
3. 登录成功，授权中心用 `Set-Cookie` 写入 SSO 会话 Cookie（默认名 `cyaim_sso`，有效期默认 8 小时），再签发授权码回调应用 A。
4. 用户随后在应用 B 里点登录 → 又跳到授权中心 `/connect/authorize`；这次浏览器**带着 `cyaim_sso` Cookie**，授权中心识别出已有会话 → **不再显示登录页**，直接签发授权码回调应用 B。

于是“登录一次，进入所有应用”。相关配置项（`CyaimAuthServerOptions`）：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `SsoCookieName` | `cyaim_sso` | SSO 会话 Cookie 名 |
| `SsoSessionLifetime` | `8h` | 会话有效期 |
| `LoginPath` | `/account/login` | 登录页路径 |
| `ServerName` | `Cyaim Auth` | 登录页标题 |
| `SsoCookieSecurePolicy` | `SameAsRequest` | Cookie 的 Secure 策略 |

安全要点（源码：`src/Cyaim.Authentication.Server/Endpoints/AccountEndpoints.cs`、`AuthorizeEndpoint.cs`）：

- **所有接入应用必须共享同一个授权中心 origin**，SSO Cookie 才能随请求带上；不同 host/端口是不同的源，不共享会话。
- 登录 POST 会校验 `Origin`/`Referer` 属于本站（防跨站强制登入）。
- 登出 `/account/logout` 或 `/connect/endsession` 清除 SSO Cookie；`post_logout_redirect_uri` 必须命中某个客户端注册的登出回调白名单才会跳转。
- **生产环境**：反向代理终止 TLS（后端收到 HTTP）时，把 `SsoCookieSecurePolicy` 设为 `CookieSecurePolicy.Always`，避免会话 Cookie 明文下发。详见 [生产部署清单](production-checklist.md)。

会话、令牌、安全戳的关系见 [令牌与会话](../concepts/tokens-and-sessions.md)。

---

## 发现文档与 JWKS

授权中心自动暴露 OIDC 发现文档，客户端与资源服务器无需硬编码端点路径：

```bash
curl http://127.0.0.1:5299/.well-known/openid-configuration
```

返回（字段来自 `src/Cyaim.Authentication.Server/Endpoints/DiscoveryEndpoints.cs`）：

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "http://127.0.0.1:5299/connect/authorize",
  "token_endpoint": "http://127.0.0.1:5299/connect/token",
  "userinfo_endpoint": "http://127.0.0.1:5299/connect/userinfo",
  "introspection_endpoint": "http://127.0.0.1:5299/connect/introspect",
  "revocation_endpoint": "http://127.0.0.1:5299/connect/revocation",
  "end_session_endpoint": "http://127.0.0.1:5299/connect/endsession",
  "jwks_uri": "http://127.0.0.1:5299/.well-known/jwks",
  "grant_types_supported": ["authorization_code", "client_credentials", "password", "refresh_token"],
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "offline_access", "permissions"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"]
}
```

`grant_types_supported` 会按你实际启用的授权类型动态生成。当授权中心用 RSA 签名（未设 `HmacSigningKey`）时，`GET /.well-known/jwks` 返回验签公钥集，第三方可据此验签而无需共享私钥。

---

## 资源服务器如何对接

资源服务器（业务 API）只需能**验证令牌**，不签发令牌，因此**不引用 Server 包**，只引用 `Cyaim.Authentication`。有两种对接方式：

### 方式一：共享 HS256 签名密钥（同一密钥）

授权中心与资源服务器配置**相同的** `HmacSigningKey`、`Issuer`、`Audience`。资源服务器无需回调授权中心即可本地验签：

```csharp
// 资源服务器 Program.cs —— 与授权中心用同一份密钥/签发者/受众
builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.Audience = "my-api";
    o.HmacSigningKey = "至少32字节的共享签名密钥..........";  // 与授权中心一致
}).AddInMemoryStore();

var app = builder.Build();
app.UseCyaimAuthentication();

app.MapGet("/api/orders", () => "...").RequirePermission("demo.order.read");
app.Run();
```

这是 `samples/Sample.WebApi` 采用的方式，简单、无网络往返，适合第一方服务共享同一密钥的场景。保护 API 的完整做法见 [保护 ASP.NET Core API](protect-aspnetcore.md)。

### 方式二：RSA + 指向 issuer（不共享私钥）

授权中心不设 `HmacSigningKey`（自动用 RSA），资源服务器从授权中心的 JWKS 获取公钥验签。这样私钥只留在授权中心，适合多方/第三方资源服务器。密钥策略与轮换见 [令牌与会话](../concepts/tokens-and-sessions.md) 与 [生产部署清单](production-checklist.md)。

> 无论哪种方式，令牌若带 `perm` 声明（`IncludePermissionsInToken=true` 时），资源服务器可直接从令牌读权限，无需连回授权中心；这让资源服务器可离线判断权限。

---

## 参考示例

`samples/Sample.AuthServer/Program.cs` 是一个完整的、可直接运行的授权中心，包含本篇全部内容：

- 种子用户 `admin/Admin!123`、`alice/alice123`、`bob/bob123`；
- 种子客户端 `cyaim-admin-panel`、`wpf-client`、`wasm-client`、`demo-m2m`；
- 内嵌管理面板，浏览器打开 `/auth-admin` 用 admin 登录。

配套的资源服务器 `samples/Sample.WebApi`（共享签名密钥）、桌面客户端 `samples/Sample.Wpf`、浏览器客户端 `samples/Sample.Wasm`。示例总览见 [示例总览](../samples.md)。

---

## 相关文档

- [快速上手](../getting-started.md) —— 五种集成场景的最小代码
- [令牌与会话](../concepts/tokens-and-sessions.md) —— JWT 声明、签名、刷新令牌轮换、SSO 会话原理
- [服务器端点参考](../reference/server-endpoints.md) —— 每个 OAuth2/OIDC 端点的参数与响应速查
- [使用权限管理面板](admin-panel.md) —— 用 UI 管理用户/角色/客户端
- [保护 ASP.NET Core API](protect-aspnetcore.md) —— 资源服务器侧的权限标注
- [桌面/WASM/控制台客户端](desktop-wasm-clients.md) —— 客户端 SDK 与 PKCE 工具
- [自定义存储（EF/数据库）](custom-stores.md) —— 把 JSON 文件换成数据库
- [生产部署清单](production-checklist.md) —— 密钥、Cookie 安全、CORS、令牌有效期
- [配置参考](../reference/configuration.md) —— 全部配置项与默认值
