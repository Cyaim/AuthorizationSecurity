# 保护 ASP.NET Core API

> 用一段中间件加一个特性，为 Minimal API 与控制器端点接入 RBAC/ABAC 权限校验。

[文档中心](../README.md) / 指南（Guides）

本指南带你从零把 `Cyaim.Authentication` 接入一个 ASP.NET Core 资源服务器：注册中间件、标注端点所需权限、在业务代码里做命令式判断、配置令牌来源与自定义拒绝响应，并与原生 `[Authorize]` 协作。所有示例来自 `samples/Sample.WebApi`，可直接编译运行。

---

## 最小接入

三步即可让权限校验生效：注册服务、选存储、启用中间件。

```csharp
using Cyaim.Authentication.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "cyaim-demo";
    o.Audience = "demo-api";
    // 令牌签名密钥（HS256）。生产建议改用 RSA：o.RsaKeyFilePath = "keys/auth.pem";
    o.HmacSigningKey = "至少32字节的对称签名密钥................";
}).AddInMemoryStore();

var app = builder.Build();

app.UseCyaimAuthentication();   // 须在 UseRouting 之后；WebApplication 最简主机直接调用即可

app.MapGet("/api/orders", () => new[] { "订单-1001", "订单-1002" })
   .RequirePermission("demo.order.read");

app.MapGet("/", () => "公开端点").AllowGuest();

app.Run();
```

要点：

- `AddCyaimAuthentication(Action<CyaimAuthOptions>?)` 返回 `CyaimAuthAspNetBuilder`，可链式接 `.AddInMemoryStore()` / `.AddJsonFileStore(path)` / `.MapStore<T>()` / `.AddPolicy(...)`。存储不可省略——它提供用户、角色、权限定义等数据。
- `UseCyaimAuthentication()` 注册的中间件负责：从请求提取令牌 → 解析主体 → 对命中 `[RequirePermission]` 的端点做校验。它同时捕获端点数据源用于启动时的权限扫描。
- 默认只拦截**标注了权限要求**的端点；未标注的端点默认放行（除非开启 [`ProtectAllEndpoints`](#protectallendpoints-默认保护全部端点)）。

`AddInMemoryStore` 是演示与测试用的进程内存储；接数据库见 [自定义存储（EF/数据库）](custom-stores.md)。

---

## 标注端点所需权限

### Minimal API 链式扩展

扩展方法定义在 `CyaimAuthEndpointConventionExtensions`，作用于任意 `IEndpointConventionBuilder`：

```csharp
// 任一满足即可（OR）：具备 demo.order.read 即放行
app.MapGet("/api/orders", () => orders)
   .RequirePermission("demo.order.read");

// 多个代码任一满足
app.MapPost("/api/orders", (OrderInput input) => Results.Created(...))
   .RequirePermission("demo.order.create", "demo.order.admin");

// 全部满足（AND）
app.MapDelete("/api/orders/{index:int}", (int index) => Results.NoContent())
   .RequireAllPermissions("demo.order.delete", "demo.order.write");

// 无参：仅要求"已认证"，不校验具体权限
app.MapGet("/api/profile", (HttpContext ctx) =>
{
    var subject = ctx.GetAuthSubject();
    return Results.Ok(new { subject.Id, subject.Name, subject.Roles, subject.Scopes });
}).RequirePermission();

// 允许游客访问（覆盖上层要求与 ProtectAllEndpoints）
app.MapGet("/", () => "公开端点").AllowGuest();

// 叠加 ABAC 策略：既要有权限，还要满足命名策略
app.MapGet("/api/policy-demo", () => "偶数分钟才能看到我")
   .RequirePermission("demo.order.read")
   .RequireAuthPolicy("even-minute");
```

可用扩展一览：

| 扩展方法 | 语义 |
|---|---|
| `.RequirePermission(params string[] codes)` | 具备任一权限即放行；无参数则仅要求已认证 |
| `.RequireAllPermissions(params string[] codes)` | 须具备全部权限 |
| `.RequireAuthPolicy(string name)` | 须满足命名 ABAC 策略（可与权限叠加） |
| `.AllowGuest()` | 放行未认证主体，覆盖上层要求 |

策略通过 `.AddPolicy(name, ctx => ...)` 注册，详见 [自定义 ABAC 策略](custom-policies.md)：

```csharp
builder.Services.AddCyaimAuthentication(o => { /* ... */ })
    .AddInMemoryStore()
    .AddPolicy("even-minute", ctx => ctx.Now.Minute % 2 == 0);
```

### 控制器特性标注

同一套语义也可用特性表达。特性 `RequirePermissionAttribute` 与 `AllowGuestAttribute` 定义在 `Cyaim.Authentication.Abstractions` 命名空间：

```csharp
using Cyaim.Authentication.Abstractions;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
[RequirePermission("demo.report")]                 // 控制器级：访问任何动作都需要
public class ReportController : ControllerBase
{
    [HttpGet]
    [RequirePermission("demo.report.read")]        // 动作级：与控制器级"且"关系，两者都要满足
    public IActionResult List() => Ok(new[] { "日报", "月报" });

    [HttpGet("ping")]
    [AllowGuest]                                    // 覆盖控制器级要求
    public IActionResult Ping() => Ok("pong");
}
```

`RequirePermissionAttribute` 的关键成员（见源码 `src/Cyaim.Authentication.Abstractions/RequirePermissionAttribute.cs`）：

- 构造函数 `RequirePermissionAttribute(params string[] permissionCodes)`——为空表示仅要求已认证。
- `bool RequireAll`——`true` 要求全部满足，`false`（默认）满足任一即可。
- `string? Policy`——附加 ABAC 策略名（与权限代码同时要求）。
- 特性 `AllowMultiple = true` 且 `Inherited = true`：**多个特性之间是"且"关系**，单个特性内多个代码默认"或"。

```csharp
// 全部满足 + 叠加策略
[RequirePermission("demo.order.delete", "demo.order.write", RequireAll = true, Policy = "even-minute")]
public IActionResult Purge() => NoContent();
```

> 提示：控制器要生效需照常 `builder.Services.AddControllers();` 与 `app.MapControllers();`。

---

## 命令式权限判断

标注解决"能不能进这个端点"；进入之后的细粒度判断（某个字段能否返回、某条指令能否执行）用命令式 API。

### HttpContext 扩展

扩展定义在 `CyaimAuthHttpContextExtensions`：

```csharp
app.MapGet("/api/order/{id}", async (string id, HttpContext ctx) =>
{
    // 布尔判断
    if (!await ctx.HasPermissionAsync("demo.order.read"))
    {
        return Results.Forbid();
    }

    // 需要诊断信息时用 CheckPermissionAsync，拿到完整 AuthorizationDecision
    AuthorizationDecision d = await ctx.CheckPermissionAsync("demo.order.delete");
    bool canDelete = d.IsGranted;              // 是否放行
    var reason = d.Reason;                     // 结论原因（AuthorizationReason 枚举）

    var subject = ctx.GetAuthSubject();        // 当前主体（未认证返回游客）
    TokenState state = ctx.GetTokenState();    // None / Valid / Invalid

    return Results.Ok(new { id, subject.Name, canDelete, reason = reason.ToString() });
});
```

四个扩展的签名（`using Microsoft.AspNetCore.Http;` 即可用）：

| 方法 | 返回 | 说明 |
|---|---|---|
| `GetAuthSubject()` | `AuthSubject` | 中间件解析出的主体；未认证时为 `AuthSubject.Guest()` |
| `GetTokenState()` | `TokenState` | `None`（未携带）/ `Valid` / `Invalid` |
| `CheckPermissionAsync(string code)` | `Task<AuthorizationDecision>` | 含 `IsGranted`、`Reason`、`PermissionCode` 等 |
| `HasPermissionAsync(string code)` | `Task<bool>` | 等价于 `CheckPermissionAsync(code).IsGranted` |

`AuthorizationDecision.Reason` 的取值与含义见 [判断原因与错误码](../reference/decisions-and-errors.md)。

### 注入 IPermissionEvaluator

脱离 `HttpContext`（后台任务、领域服务）时，直接注入 `IPermissionEvaluator`：

```csharp
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;

public class OrderService(IPermissionEvaluator evaluator)
{
    public async Task<bool> CanDeleteAsync(AuthSubject subject)
    {
        // 便捷扩展：直接传权限代码，返回 AuthorizationDecision
        AuthorizationDecision decision =
            await evaluator.EvaluateAsync(subject, "demo.order.delete");
        return decision.IsGranted;

        // 仅要布尔可用 evaluator.IsGrantedAsync(subject, "demo.order.delete")
    }
}
```

`IPermissionEvaluator` 核心成员（见 `src/Cyaim.Authentication.Abstractions/Services/IPermissionEvaluator.cs`）：

- `GetPermissionSetAsync(subject)`——取主体编译后的完整权限集。
- `EvaluateAsync(subject, PermissionQuery, context?, ct)`——底层判断；扩展方法 `EvaluateAsync(subject, string code, ...)` 与 `IsGrantedAsync(subject, string code, ...)` 更常用。
- `EvaluatePolicyAsync(subject, policyName, context?, ct)`——评估命名 ABAC 策略。

`HttpContext.CheckPermissionAsync` 内部正是解析出 `IPermissionEvaluator` 再对 `GetAuthSubject()` 调 `EvaluateAsync`。

---

## 配置令牌来源

中间件从三处按顺序提取令牌：`Authorization` 头 → 查询字符串 → Cookie。相关选项在 `CyaimAuthOptions`：

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.HmacSigningKey = "至少32字节的对称签名密钥................";

    // 请求头（默认 Authorization，Bearer 方案）
    o.AuthorizationHeaderName = "Authorization";

    // 查询字符串（WebSocket 握手常用），默认开启，参数名 access_token
    o.AllowTokenFromQuery = true;
    o.QueryTokenParameter = "access_token";

    // Cookie（默认关闭）
    o.AllowTokenFromCookie = false;
    o.CookieTokenName = "cyaim_token";
}).AddInMemoryStore();
```

三种来源分别对应下列请求写法：

```http
GET /api/orders HTTP/1.1
Authorization: Bearer eyJhbGciOi...
```

```http
GET /api/orders?access_token=eyJhbGciOi... HTTP/1.1
```

```http
GET /api/orders HTTP/1.1
Cookie: cyaim_token=eyJhbGciOi...
```

> 查询字符串令牌主要服务于浏览器 WebSocket 握手（无法自定义请求头）。普通 API 建议只用 `Authorization` 头，可将 `AllowTokenFromQuery` 设为 `false` 收紧攻击面。WebSocket 场景见 [WebSocket 鉴权](websocket.md)。

---

## 自定义拒绝响应（OnDenied）

默认拒绝会写一段 JSON：`{ "error": ..., "error_description": <Reason>, "permission": <code> }`，并对 401 设置 `WWW-Authenticate` 头。若要替换为自定义响应，设置 `OnDenied`：

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.HmacSigningKey = "至少32字节的对称签名密钥................";

    o.OnDenied = async (context, decision) =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        context.Response.ContentType = "application/json; charset=utf-8";
        await context.Response.WriteAsJsonAsync(new
        {
            code = "forbidden",
            reason = decision?.Reason.ToString(),        // AuthorizationReason，可能为 null
            permission = decision?.PermissionCode,
            traceId = context.TraceIdentifier,
        });
    };
}).AddInMemoryStore();
```

`OnDenied` 的签名是 `Func<HttpContext, AuthorizationDecision?, Task>`（见 `src/Cyaim.Authentication/AspNetCore/CyaimAuthOptions.cs`）。设置后完全接管拒绝响应，你需要自己写状态码与响应体。`decision` 可能为 `null`（例如令牌无效在校验具体权限之前就被拒）。

拒绝是否写审计日志由 `o.AuditDenials`（默认 `true`）控制。

---

## 与原生 [Authorize] 协作

框架注册了一个策略提供器，把 `cyaim:` 前缀的策略名桥接到权限引擎。于是可以直接用 ASP.NET Core 原生的 `[Authorize(Policy = "cyaim:<权限代码>")]`：

```csharp
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/[controller]")]
public class InvoiceController : ControllerBase
{
    [HttpGet]
    [Authorize(Policy = "cyaim:demo.invoice.read")]   // 由 Cyaim 权限引擎评估
    public IActionResult List() => Ok();
}
```

机制（见 `src/Cyaim.Authentication/AspNetCore/PolicyBridge/CyaimPermissionPolicy.cs`）：

- `CyaimPermissionPolicyProvider` 识别 `cyaim:` 前缀（常量 `PolicyPrefix`），截掉前缀得到权限代码，构造 `CyaimPermissionRequirement`；其余策略名委托默认提供器。
- `CyaimPermissionAuthorizationHandler` 从 `HttpContext` 取 `GetAuthSubject()`（或从 `ClaimsIdentity` 还原主体），调 `IPermissionEvaluator.EvaluateAsync` 判断。

何时用哪种？

- 端点只经 Cyaim 中间件校验：用 `[RequirePermission]` / `.RequirePermission()`。
- 已在用 ASP.NET Core 授权管线（`app.UseAuthorization()`、`[Authorize]` 混用）：用 `[Authorize(Policy = "cyaim:...")]` 让两套体系走同一引擎。

> 桥接要经过原生授权管线，需照常启用 `app.UseAuthentication()` / `app.UseAuthorization()` 并保证请求主体能被识别。若只用 Cyaim 中间件，`[RequirePermission]` 路径无需额外启用原生授权。

---

## ProtectAllEndpoints：默认保护全部端点

默认（`ProtectAllEndpoints = false`）只拦截标注了 `[RequirePermission]` 的端点，其余放行。设为 `true` 后，**所有端点默认要求已认证**，未标注权限的端点也会拦截，只有 `[AllowGuest]` / `[AllowAnonymous]` 能放行：

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.HmacSigningKey = "至少32字节的对称签名密钥................";
    o.ProtectAllEndpoints = true;   // 默认拒绝，白名单放行
}).AddInMemoryStore();

app.MapGet("/", () => "首页").AllowGuest();          // 显式放行
app.MapGet("/health", () => "ok").AllowGuest();       // 显式放行
app.MapGet("/api/orders", () => orders)
   .RequirePermission("demo.order.read");             // 照常按权限校验
```

这对"默认关闭、按需开放"的安全姿态更友好，避免新增端点忘记标注而意外裸奔。开启后请梳理所有公开端点并逐一 `.AllowGuest()`。

---

## 完整示例

`samples/Sample.WebApi/Program.cs` 是一个端到端的资源服务器：Minimal API、控制器、WebSocket 三种端点形态，含 ABAC 策略、角色层级与拒绝优先演示，并在启动时为种子用户打印可直接 `curl` 测试的令牌。运行：

```bash
cd samples/Sample.WebApi
dotnet run
```

控制台会打印 alice / bob / carol 三个演示用户的令牌，随后即可：

```bash
# 用 alice（order-admin）读取订单
curl -H "Authorization: Bearer <alice-token>" http://localhost:5000/api/orders
```

---

## 相关文档

- [快速上手](../getting-started.md) —— 五种集成场景的最小可运行代码
- [WebSocket 鉴权](websocket.md) —— 握手鉴权与消息级细粒度判断
- [权限模型](../concepts/permission-model.md) —— 权限代码、通配符、拒绝优先、RBAC/ABAC
- [权限代码语法](../reference/permission-codes.md) —— 匹配规则与示例表
- [自定义 ABAC 策略](custom-policies.md) —— `AddPolicy`、`AuthorizationContext`、`RequireAuthPolicy`
- [自定义存储（EF/数据库）](custom-stores.md) —— 六个存储接口与 `MapStore<T>`
- [配置参考](../reference/configuration.md) —— `CyaimAuthOptions` 每一项默认值
- [判断原因与错误码](../reference/decisions-and-errors.md) —— `AuthorizationReason` 与 HTTP 结果
- [公开 API 参考](../reference/api.md) —— 类型与成员签名
