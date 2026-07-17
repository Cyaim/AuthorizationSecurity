// 生产集群示例：多个实例共享同一个数据库（SQLite 文件模拟共享库；生产换成 PostgreSQL/SQL Server）
// 组成集群——共享数据 + 共享签名密钥 + 数据库集群版本驱动的跨实例缓存失效，无需 Redis。
//
// 跑法（同机两实例，见 README.md）：
//   环境变量 CYAIM_DB 指向同一个 .db 文件；两实例监听不同端口。
//   在一个实例的 /auth-admin 改某用户/角色权限，另一个实例在轮询间隔内即生效。

using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Core;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// 本实例标识（用于观察是哪个实例响应）
string instanceId = Environment.GetEnvironmentVariable("CYAIM_INSTANCE")
    ?? $"inst-{Environment.ProcessId}";

// 共享数据库文件（所有实例必须一致）；生产改为服务器数据库连接串
string dbPath = Environment.GetEnvironmentVariable("CYAIM_DB")
    ?? Path.Combine(AppContext.BaseDirectory, "cluster-shared.db");
string conn = $"Data Source={dbPath}";

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "cyaim-cluster";
    o.Audience = "cluster-api";
    // 所有实例共享同一签名密钥（生产从密钥管理/配置注入，切勿用自动生成的开发密钥）
    o.HmacSigningKey = builder.Configuration["Auth:SigningKey"]
        ?? "cluster-demo-shared-signing-key-32byte!!";
})
.Core
// EF Core 共享数据库存储 + 数据库集群版本（跨实例缓存失效），轮询间隔 3 秒
.AddCyaimAuthEntityFrameworkStores(
    db => db.UseSqlite(conn),
    cluster => cluster.RefreshInterval = TimeSpan.FromSeconds(3));

builder.Services.AddCyaimAuthServer(o => o.ServerName = "Cyaim 集群演示");
builder.Services.AddCyaimAuthAdminPanel();

var app = builder.Build();

// 建库（演示用 EnsureCreated；生产用 EF 迁移）
await app.Services.EnsureCyaimAuthDatabaseCreatedAsync();

app.UseCyaimAuthentication();
app.MapCyaimAuthServer();
app.MapCyaimAuthAdmin();

// 观察端点：当前实例标识 + 该实例看到的集群版本（改数据后另一实例的版本会在轮询后追上）
app.MapGet("/instance", (IServiceProvider sp) => Results.Ok(new
{
    instance = instanceId,
    clusterVersion = sp.GetRequiredService<Cyaim.Authentication.Abstractions.Stores.IAuthStoreVersion>().Version,
})).AllowGuest();

app.MapGet("/", () => Results.Content($"""
    <!doctype html><meta charset="utf-8"><title>Cyaim 集群演示</title>
    <body style="font-family:system-ui;max-width:640px;margin:48px auto;line-height:1.8">
    <h1>Cyaim 集群演示 —— 实例 {instanceId}</h1>
    <ul>
      <li><a href="/auth-admin">权限管理面板</a>（admin / Admin!123）</li>
      <li><a href="/instance">/instance</a>（本实例看到的集群版本）</li>
      <li><a href="/api/orders">/api/orders</a>（受保护，需要 demo.order.read）</li>
    </ul>
    <p>启动第二个实例并指向同一个数据库文件（环境变量 <code>CYAIM_DB</code>），在任一实例的管理面板修改权限，
    另一实例在约 3 秒轮询后即生效。</p>
    </body>
    """, "text/html; charset=utf-8")).AllowGuest();

app.MapGet("/api/orders", () => new[] { "订单-1001", "订单-1002" })
   .RequirePermission("demo.order.read");

// 幂等播种（多实例并发启动安全：唯一性冲突被忽略）
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();
    try
    {
        await seeder.EnsureRoleAsync("admin", new[] { AuthConstants.AdminPermissions.All, "demo.**" }, displayName: "管理员", isSystem: true);
        await seeder.EnsureRoleAsync("order-viewer", new[] { "demo.order.read" }, displayName: "订单查看");
        await seeder.EnsureUserAsync("admin", "Admin!123", roles: new[] { "admin" }, displayName: "管理员");
        await seeder.EnsureUserAsync("alice", "alice123", roles: new[] { "order-viewer" }, displayName: "Alice");
        await seeder.EnsureClientAsync("cyaim-admin-panel", null,
            new[] { AuthConstants.GrantTypes.Password, AuthConstants.GrantTypes.RefreshToken },
            allowedScopes: new[] { AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
            allowOfflineAccess: true, clientName: "管理面板");
    }
    catch (InvalidOperationException)
    {
        // 另一实例已并发播种，忽略唯一性冲突
    }
}

app.Run();
