// 资源服务器示例：权限中间件 + Minimal API / 控制器 / WebSocket 三种端点形态。
// 演示便利：启动时为种子用户直接签发令牌打印到控制台，便于 curl / wscat 测试。
// 生产环境令牌应由授权服务器（Sample.AuthServer）颁发，本服务仅校验。

using System.Net.WebSockets;
using System.Text;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;

var builder = WebApplication.CreateBuilder(args);

const string SharedKey = "demo-shared-signing-key-32bytes!!";  // 与授权服务器共享（演示用）

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "cyaim-demo";
    o.Audience = "demo-api";
    o.HmacSigningKey = SharedKey;
    o.AuditFilePath = "logs/audit.jsonl";
}).AddInMemoryStore()
  .AddPolicy("even-minute", ctx => ctx.Now.Minute % 2 == 0);   // ABAC 策略演示

builder.Services.AddControllers();

var app = builder.Build();

app.UseWebSockets();
app.UseCyaimAuthentication();

// ---------- 种子数据 ----------
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();
    await seeder.EnsureRoleAsync("order-viewer", new[] { "demo.order.read" });
    await seeder.EnsureRoleAsync("order-admin", new[] { "demo.order.**", "demo.ws.**" },
        parentRoles: new[] { "order-viewer" });
    // 拒绝优先演示：受限管理员被显式拒绝删除
    await seeder.EnsureRoleAsync("order-admin-restricted",
        parentRoles: new[] { "order-admin" },
        permissions: Array.Empty<string>(),
        deniedPermissions: new[] { "demo.order.delete" });

    await seeder.EnsureUserAsync("alice", "alice123", roles: new[] { "order-admin" }, displayName: "Alice 管理员");
    await seeder.EnsureUserAsync("bob", "bob123", roles: new[] { "order-viewer" }, displayName: "Bob 只读");
    await seeder.EnsureUserAsync("carol", "carol123", roles: new[] { "order-admin-restricted" }, displayName: "Carol 受限管理员");
}

// ---------- Minimal API ----------
var orders = new List<string> { "订单-1001", "订单-1002" };

app.MapGet("/", () => "Sample.WebApi 运行中。公开端点，无需令牌。").AllowGuest();

app.MapGet("/api/orders", () => orders)
   .RequirePermission("demo.order.read");

app.MapPost("/api/orders", (OrderInput input) => { orders.Add(input.Name); return Results.Created($"/api/orders/{orders.Count - 1}", input.Name); })
   .RequirePermission("demo.order.create");

app.MapDelete("/api/orders/{index:int}", (int index) =>
{
    if (index < 0 || index >= orders.Count) return Results.NotFound();
    orders.RemoveAt(index);
    return Results.NoContent();
}).RequirePermission("demo.order.delete");

app.MapGet("/api/profile", (HttpContext ctx) =>
{
    var subject = ctx.GetAuthSubject();
    return Results.Ok(new { subject.Id, subject.Name, subject.Roles, subject.Scopes });
}).RequirePermission();   // 仅要求已认证

app.MapGet("/api/policy-demo", () => "偶数分钟才能看到我")
   .RequirePermission("demo.order.read")
   .RequireAuthPolicy("even-minute");

// ---------- 控制器 ----------
app.MapControllers();

// ---------- WebSocket ----------
app.Map("/ws/echo", async (HttpContext context) =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    // 握手已由权限中间件校验 demo.ws.connect（令牌来自 ?access_token= 或 Authorization 头）
    using WebSocket ws = await context.WebSockets.AcceptWebSocketAsync();
    var subject = context.GetAuthSubject();
    var buffer = new byte[4096];

    while (ws.State == WebSocketState.Open)
    {
        var result = await ws.ReceiveAsync(buffer, context.RequestAborted);
        if (result.MessageType == WebSocketMessageType.Close)
        {
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", context.RequestAborted);
            break;
        }

        string text = Encoding.UTF8.GetString(buffer, 0, result.Count);

        // 消息级细粒度权限：广播指令需要额外权限
        if (text.StartsWith("/broadcast", StringComparison.OrdinalIgnoreCase) &&
            !await context.HasPermissionAsync("demo.ws.broadcast"))
        {
            await Send(ws, "错误：缺少 demo.ws.broadcast 权限");
            continue;
        }

        await Send(ws, $"[{subject.Name}] {text}");
    }

    static Task Send(WebSocket ws, string message) =>
        ws.SendAsync(Encoding.UTF8.GetBytes(message), WebSocketMessageType.Text, true, CancellationToken.None);
}).RequirePermission("demo.ws.connect");

// ---------- 演示令牌 ----------
using (var scope = app.Services.CreateScope())
{
    var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
    var users = scope.ServiceProvider.GetRequiredService<Cyaim.Authentication.Abstractions.Stores.IUserStore>();
    var evaluator = scope.ServiceProvider.GetRequiredService<IPermissionEvaluator>();
    var logger = app.Services.GetRequiredService<ILogger<Program>>();

    foreach (string name in new[] { "alice", "bob", "carol" })
    {
        AuthUser user = (await users.FindByUserNameAsync(name))!;
        var subject = new AuthSubject
        {
            Id = user.Id,
            Name = user.DisplayName,
            IsAuthenticated = true,
            Roles = user.Roles.ToArray(),
            Claims = new Dictionary<string, string>
            {
                [AuthConstants.ClaimTypes.PreferredUserName] = user.UserName,
                [AuthConstants.ClaimTypes.SecurityStamp] = user.SecurityStamp,
            },
        };
        var set = await evaluator.GetPermissionSetAsync(subject);
        var issued = await tokens.IssueAccessTokenAsync(new AccessTokenRequest
        {
            Subject = subject,
            Scopes = new[] { AuthConstants.Scopes.Permissions },
            IncludePermissionClaims = true,
            PermissionCodes = set.Allows,
        });
        logger.LogInformation("演示令牌 {User}（角色 {Roles}）：\n{Token}\n", name, string.Join(",", user.Roles), issued.Token);
    }
}

app.Run();

record OrderInput(string Name);
