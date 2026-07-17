# 自定义 ABAC 策略

> 在角色/权限（RBAC）之上叠加命名的属性判断（ABAC）：注册策略、在端点要求它，实现「仅资源所有者」「仅工作时间」这类基于上下文的规则。面包屑：[文档中心](../README.md) / 指南

权限代码（RBAC）回答「这个主体有没有 `sys.user.edit` 权限」；但很多规则依赖**运行时属性**——请求的是不是自己的资源？当前是不是工作时间？来源 IP 在不在白名单？这类判断用 **ABAC 策略**：一个命名的布尔函数，输入是[鉴权上下文](#授权上下文-authorizationcontext)，与权限代码组合使用。

策略是 `IAuthPolicy`（`src/Cyaim.Authentication.Abstractions/Authorization/AuthorizationContext.cs`），注册进 `AuthPolicyRegistry`（`src/Cyaim.Authentication.Core/Engine/AuthPolicyRegistry.cs`），由评估器的 `EvaluatePolicyAsync` 调用。

---

## 注册策略：三种 AddPolicy 重载

在 `AddCyaimAuthentication(...)` 返回的构建器上链式注册（也可在核心构建器 `AddCyaimAuthCore(...)` 上，签名一致，见 `CyaimAuthCoreServiceCollectionExtensions.cs`）。策略名**不区分大小写**、唯一。

```csharp
builder.Services
    .AddCyaimAuthentication(o => o.Issuer = "https://auth.example.com")
    .AddInMemoryStore()

    // 1) 同步委托：ctx => bool
    .AddPolicy("working-hours", ctx => IsWorkingHours(ctx.Now))

    // 2) 异步委托：(ctx, ct) => Task<bool>（可访问数据库/远程服务）
    .AddPolicy("in-department", async (ctx, ct) =>
    {
        // ... 异步查库判断 ...
        return await CheckDepartmentAsync(ctx.Subject.Id, ct);
    })

    // 3) 策略类型：TPolicy : IAuthPolicy
    .AddPolicy<ResourceOwnerPolicy>();
```

三个重载的实际签名（`CyaimAuthCoreBuilder`，ASP.NET Core 的 `CyaimAuthAspNetBuilder` 原样代理）：

```csharp
CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, bool> evaluate);
CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate);
CyaimAuthCoreBuilder AddPolicy<TPolicy>() where TPolicy : class, IAuthPolicy;
```

前两个用委托，内部包成 `DelegateAuthPolicy`；第三个注册你自己的 `IAuthPolicy` 实现类型。

> 三种重载都以**单例**注册策略，且 `AuthPolicyRegistry` 在容器构建时一次性从全部 `IAuthPolicy` 建索引。因此策略实现**必须无状态、可并发**（接口文档明确要求）。`AddPolicy<TPolicy>()` 的构造函数只能注入单例服务；若策略要访问 Scoped 资源（如 `DbContext`），请注入 `IServiceScopeFactory` 或 `IDbContextFactory<T>` 在 `EvaluateAsync` 内按需建作用域，而不是直接注入 Scoped 服务。

### 实现 IAuthPolicy

```csharp
using Cyaim.Authentication.Abstractions.Authorization;
using Microsoft.AspNetCore.Http;

public sealed class ResourceOwnerPolicy : IAuthPolicy
{
    public string Name => "resource-owner";

    public Task<bool> EvaluateAsync(AuthorizationContext context, CancellationToken cancellationToken = default)
    {
        // 仅当路由里的 {userId} 等于当前主体自己的 Id 时放行
        if (!context.Subject.IsAuthenticated)
            return Task.FromResult(false);
        if (context.UnderlyingContext is not HttpContext http)
            return Task.FromResult(false);

        string? routeUserId = http.Request.RouteValues["userId"]?.ToString();
        bool isOwner = routeUserId != null &&
                       string.Equals(routeUserId, context.Subject.Id, StringComparison.Ordinal);
        return Task.FromResult(isOwner);
    }
}
```

---

## 授权上下文 AuthorizationContext

策略评估时能拿到的属性（`AuthorizationContext.cs`）：

| 属性 | 类型 | 说明 |
|---|---|---|
| `Subject` | `AuthSubject` | 被判断的主体（`Id`、`Name`、`IsAuthenticated`、`Roles`、`Scopes`、`ClientId`、`SessionId`、`Claims` 等） |
| `PermissionCode` | `string?` | 正在判断的权限代码（若有） |
| `Items` | `IDictionary<string, object?>` | 资源与环境属性（键不区分大小写，如 `resource.ownerId`）。**端点自动评估时为空**，需你自行填充（见下） |
| `UnderlyingContext` | `object?` | 宿主原生上下文。ASP.NET Core 端点评估时为 `HttpContext`，策略可 `as HttpContext` 后读路由/查询/头/`User` |
| `Now` | `DateTimeOffset` | 评估时刻。中间件构造的上下文里为 **UTC**（`DateTimeOffset.UtcNow`）；做本地工作时间判断要用 `TimeZoneInfo` 转换 |

**重要**：端点被中间件自动评估时（`.RequireAuthPolicy(...)` / `[RequirePermission(Policy=...)]`），框架构造的上下文只填了 `Subject` 与 `UnderlyingContext`（= `HttpContext`），**不填 `Items`**（见 `CyaimAuthMiddleware.cs`）。所以策略在端点场景要从 `HttpContext` 自取属性（路由值、查询串、`http.User` 的声明等）。`Items` 主要用于[命令式调用](#命令式调用策略)时你手工塞入属性。

`AuthSubject.Claims` 是 `IReadOnlyDictionary<string,string>`，承载令牌里的附加声明（如部门、租户），是 ABAC 属性的常用来源。

---

## 在端点要求策略

### Minimal API 链式

```csharp
app.MapGet("/api/users/{userId}/profile", GetProfile)
   .RequirePermission("sys.user.read")     // 先过 RBAC 权限
   .RequireAuthPolicy("resource-owner");   // 再过 ABAC 策略
```

`RequireAuthPolicy(name)`（`CyaimAuthEndpointConventionExtensions.cs`）给端点加一条纯策略规则。它与 `RequirePermission(...)` 是**「且」**关系：多条规则全部满足才放行。

### 特性标注（控制器/方法）

```csharp
// 权限代码 + 策略：两者都要满足
[RequirePermission("sys.user.edit", Policy = "resource-owner")]
[HttpPut("/api/users/{userId}")]
public IActionResult Update(string userId) { /* ... */ }

// 仅策略（不带权限代码）：只要求已认证 + 满足策略
[RequirePermission(Policy = "working-hours")]
[HttpPost("/api/reports/run")]
public IActionResult RunReport() { /* ... */ }
```

`RequirePermissionAttribute`（`src/Cyaim.Authentication.Abstractions/RequirePermissionAttribute.cs`）的 `Policy` 属性与其 `PermissionCodes` 在同一特性内一起要求；多个特性之间为「且」。

---

## fail-closed（拒绝优先）语义

策略评估是**保守失败**的——不确定就拒绝。评估逻辑在 `PermissionEvaluator.EvaluatePolicyAsync`：

- 策略**未注册**（名字打错、忘了 `AddPolicy`）→ 拒绝，原因 `PolicyNotFound`，并记 Warning 日志。
- 策略委托/`EvaluateAsync` **抛异常**（除 `OperationCanceledException`）→ 拒绝，原因 `PolicyNotSatisfied`，记 Error 日志。异常不会「漏过」变成放行。
- 策略返回 `false` → 拒绝，原因 `PolicyNotSatisfied`。
- 策略返回 `true` → 放行，原因 `GrantedByPolicy`。

这些原因码见[判断原因与错误码参考](../reference/decisions-and-errors.md)。含义是：**策略只能是「额外的门槛」，永远不会因为它出错而放宽访问**。所以策略里可以放心地对边界情况直接 `return false`（如拿不到 `HttpContext`、拿不到路由值）。

---

## 实例一：仅资源所有者

只允许用户访问「属于自己」的资源。用委托实现最简：

```csharp
builder.Services
    .AddCyaimAuthentication(/* ... */)
    .AddInMemoryStore()
    .AddPolicy("resource-owner", ctx =>
    {
        if (!ctx.Subject.IsAuthenticated) return false;
        if (ctx.UnderlyingContext is not HttpContext http) return false;

        // 路由 /api/users/{userId}/... 中的 userId 必须等于自己
        string? routeUserId = http.Request.RouteValues["userId"]?.ToString();
        return routeUserId != null &&
               string.Equals(routeUserId, ctx.Subject.Id, StringComparison.Ordinal);
    });
```

端点：

```csharp
app.MapGet("/api/users/{userId}/orders", (string userId) => /* ... */)
   .RequirePermission("shop.order.read")   // 有读订单权限
   .RequireAuthPolicy("resource-owner");   // 且只能读自己的
```

管理员要能读任何人的订单？给管理员单独一个不带 `resource-owner` 的端点，或在策略里放行带某权限/角色的主体：

```csharp
.AddPolicy("resource-owner", ctx =>
{
    if (!ctx.Subject.IsAuthenticated) return false;
    if (ctx.Subject.Roles.Contains("admin")) return true;   // 管理员豁免
    if (ctx.UnderlyingContext is not HttpContext http) return false;
    string? routeUserId = http.Request.RouteValues["userId"]?.ToString();
    return string.Equals(routeUserId, ctx.Subject.Id, StringComparison.Ordinal);
});
```

## 实例二：仅工作时间

只在工作日 09:00–18:00（按某时区）放行。注意 `ctx.Now` 是 **UTC**，须转成目标时区再判断：

```csharp
builder.Services
    .AddCyaimAuthentication(/* ... */)
    .AddInMemoryStore()
    .AddPolicy("working-hours", ctx =>
    {
        // Windows 用 "China Standard Time"；Linux/macOS 用 IANA "Asia/Shanghai"
        TimeZoneInfo tz = TimeZoneInfo.FindSystemTimeZoneById("Asia/Shanghai");
        DateTime local = TimeZoneInfo.ConvertTime(ctx.Now, tz).DateTime;

        bool weekday = local.DayOfWeek is not (DayOfWeek.Saturday or DayOfWeek.Sunday);
        bool inHours = local.Hour is >= 9 and < 18;
        return weekday && inHours;
    });
```

端点（仅策略，不叠加权限代码时，等价于「已认证 + 工作时间」）：

```csharp
app.MapPost("/api/payroll/export", ExportPayroll)
   .RequirePermission("hr.payroll.export")
   .RequireAuthPolicy("working-hours");
```

> 若跨时区部署且时区数据缺失，`FindSystemTimeZoneById` 会抛异常——按 fail-closed 语义，这会被评估器捕获并按拒绝处理，不会误放行。生产可预先缓存 `TimeZoneInfo` 实例（无状态、可并发），避免每次查找。

---

## 命令式调用策略

端点自动评估外，也可在业务代码里手动评估策略——此时你能自行填充 `AuthorizationContext.Items`。注入 `IPermissionEvaluator`：

```csharp
public sealed class ReportService
{
    private readonly IPermissionEvaluator _evaluator;
    public ReportService(IPermissionEvaluator evaluator) => _evaluator = evaluator;

    public async Task<bool> CanExportAsync(AuthSubject subject, string ownerId, CancellationToken ct)
    {
        var ctx = new AuthorizationContext
        {
            Subject = subject,
            Now = DateTimeOffset.UtcNow,
        };
        ctx.Items["resource.ownerId"] = ownerId;   // 手工塞入资源属性

        AuthorizationDecision decision =
            await _evaluator.EvaluatePolicyAsync(subject, "resource-owner-by-item", ctx, ct);
        return decision.IsGranted;
    }
}
```

对应的策略从 `Items` 读属性：

```csharp
.AddPolicy("resource-owner-by-item", ctx =>
{
    if (!ctx.Subject.IsAuthenticated) return false;
    return ctx.Items.TryGetValue("resource.ownerId", out object? owner)
        && owner is string s
        && string.Equals(s, ctx.Subject.Id, StringComparison.Ordinal);
});
```

> ASP.NET Core 里也可用 `HttpContext` 的 `CheckPermissionAsync(code)` / `HasPermissionAsync(code)` 做命令式**权限代码**检查（见 [WebSocket 鉴权](websocket.md)），但那两个扩展只判断权限代码、不评估策略。要命令式判断策略，用上面的 `IPermissionEvaluator.EvaluatePolicyAsync`。

---

## 相关文档

- [权限模型](../concepts/permission-model.md) — RBAC 与 ABAC 如何协作
- [权限代码语法参考](../reference/permission-codes.md) — 与策略组合的权限代码
- [判断原因与错误码参考](../reference/decisions-and-errors.md) — `GrantedByPolicy` / `PolicyNotSatisfied` / `PolicyNotFound`
- [保护 ASP.NET Core API](protect-aspnetcore.md) — `RequirePermission` / `RequireAuthPolicy` 端点标注全貌
- [自定义存储](custom-stores.md) — 另一类扩展点
