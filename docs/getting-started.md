# 快速上手

> 五种集成场景的最小可运行代码。面包屑：[文档中心](README.md) / 入门。从 1.x 迁移见 [从 1.x 迁移](migration-1x.md)。

深入阅读：[架构总览](concepts/architecture.md) · [权限模型](concepts/permission-model.md) · [配置参考](reference/configuration.md)。

## 场景一：给现有 ASP.NET Core API 加权限（最小接入）

```xml
<PackageReference Include="Cyaim.Authentication" Version="2.0.0" />
```

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";      // 令牌签发者
    o.Audience = "my-api";
    o.HmacSigningKey = "至少32字节的共享签名密钥..........";  // 或留空自动生成 RSA 密钥
}).AddInMemoryStore();                           // 或 .AddJsonFileStore("auth-data.json")

var app = builder.Build();

app.UseCyaimAuthentication();                    // 权限中间件

// Minimal API：链式标注
app.MapGet("/api/users", () => ...).RequirePermission("sys.user.read");
app.MapDelete("/api/users/{id}", (string id) => ...).RequirePermission("sys.user.delete");
app.MapGet("/api/public", () => "hello").AllowGuest();

app.Run();
```

控制器风格：

```csharp
[RequirePermission("sys.user")]                  // 控制器级
public class UserController : ControllerBase
{
    [HttpGet]
    [RequirePermission("sys.user.read")]         // 动作级（与控制器级同时要求）
    public IActionResult List() => Ok(...);

    [HttpGet("ping")]
    [AllowGuest]                                 // 免鉴权
    public IActionResult Ping() => Ok("pong");
}
```

权限代码语义：`.` 分层、`*` 匹配一段、`**` 匹配任意后代、拒绝优先。给用户/角色授予 `sys.user.**` 即可访问上述全部端点。

## 场景二：独立授权服务器 + SSO + 管理面板

```xml
<PackageReference Include="Cyaim.Authentication.Server" Version="2.0.0" />
<PackageReference Include="Cyaim.Authentication.AdminPanel" Version="2.0.0" />
```

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.Audience = "my-api";
}).AddJsonFileStore("auth-data.json");

builder.Services.AddCyaimAuthServer();           // OAuth2/OIDC 端点 + SSO
builder.Services.AddCyaimAuthAdminPanel();       // /auth-admin 管理面板

var app = builder.Build();
app.UseCyaimAuthentication();
app.MapCyaimAuthServer();
app.MapCyaimAuthAdmin();

// 首次启动播种管理员
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();
    await seeder.EnsureRoleAsync("admin", new[] { AuthConstants.AdminPermissions.All }, isSystem: true);
    await seeder.EnsureUserAsync("admin", "ChangeMe!123", roles: new[] { "admin" });
    await seeder.EnsureClientAsync("cyaim-admin-panel", null,
        new[] { AuthConstants.GrantTypes.Password },
        allowedScopes: new[] { "permissions", "offline_access" },
        allowOfflineAccess: true);
}

app.Run();
```

启动后：

- 发现文档：`GET /.well-known/openid-configuration`
- 管理面板：浏览器打开 `/auth-admin`，用 admin 登录
- 各业务应用把 `Issuer/Audience/签名密钥` 指向该服务器即可统一登录（授权码 + PKCE 流经 `/connect/authorize`，共享 SSO 会话 Cookie）

## 场景三：WinForms / WPF / 控制台客户端

```xml
<PackageReference Include="Cyaim.Authentication.Client" Version="2.0.0" />
```

```csharp
var client = new CyaimAuthClient(new CyaimAuthClientOptions
{
    Authority = "https://auth.example.com",
    ClientId = "wpf-app",
    Scopes = { "permissions", "offline_access" },
}, cache: new FileTokenCache("token-cache.json"));

await client.LoginWithPasswordAsync(userBox.Text, passBox.Password);
await client.LoadPermissionsAsync();

// UI 权限门控
btnDelete.IsEnabled = client.HasPermission("sys.user.delete");

// 调 API 自动附加/刷新令牌
var http = new HttpClient(new CyaimAuthHttpMessageHandler(client));
var users = await http.GetStringAsync("https://api.example.com/api/users");
```

## 场景四：Blazor WebAssembly

`Cyaim.Authentication.Client` 是 netstandard2.0 纯托管库，可直接在 WASM 使用；推荐授权码 + PKCE：

```csharp
// 生成登录跳转
var verifier = Pkce.CreateCodeVerifier();
var url = Pkce.BuildAuthorizeUrl(authority, clientId, redirectUri,
    scopes, state, Pkce.CreateCodeChallenge(verifier));
Navigation.NavigateTo(url, forceLoad: true);

// 回调页兑换
await client.ExchangeAuthorizationCodeAsync(code, redirectUri, verifier);
```

`CyaimAuthHttpMessageHandler` 可直接注册进 `builder.Services.AddHttpClient(...)`。

## 场景五：WebSocket

握手时中间件已从 `?access_token=` 或 `Authorization` 头完成鉴权：

```csharp
app.Map("/ws", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
    using var ws = await context.WebSockets.AcceptWebSocketAsync();
    // 消息级细粒度判断
    if (await context.HasPermissionAsync("chat.message.send")) { ... }
}).RequirePermission("chat.connect");
```

## 命令式判断与 ABAC 策略

```csharp
// 任意位置注入 IPermissionEvaluator
var decision = await evaluator.EvaluateAsync(subject, "sys.order.export");
if (!decision.IsGranted) Console.WriteLine(decision.Reason);

// 注册命名策略（可与权限码组合）
services.AddCyaimAuthentication(...)
    .AddPolicy("working-hours", ctx => ctx.Now.LocalDateTime.Hour is >= 9 and < 18);

app.MapPost("/api/transfer", ...)
   .RequirePermission("finance.transfer")
   .RequireAuthPolicy("working-hours");
```

## 与原生 [Authorize] 协作

```csharp
[Authorize(Policy = "cyaim:sys.user.read")]      // 由权限引擎评估
public IActionResult List() => Ok(...);
```
