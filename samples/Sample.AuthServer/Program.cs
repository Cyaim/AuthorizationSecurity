// 授权中心示例：OAuth2/OIDC 端点 + 统一登录（SSO）+ 内嵌权限管理面板。
// 数据持久化在 data/auth-store.json，删除该文件即重置。

using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Core;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "cyaim-demo-auth";
    o.Audience = "demo-api";
    o.HmacSigningKey = "demo-shared-signing-key-32bytes!!";   // 资源服务（Sample.WebApi）用同一密钥校验
    o.AuditFilePath = "logs/audit.jsonl";
}).AddJsonFileStore("data/auth-store.json");

builder.Services.AddCyaimAuthServer(o =>
{
    o.ServerName = "Cyaim 演示授权中心";
});

builder.Services.AddCyaimAuthAdminPanel();

var app = builder.Build();

app.UseCyaimAuthentication();
app.MapCyaimAuthServer();
app.MapCyaimAuthAdmin();

app.MapGet("/", () => Results.Content($$"""
    <!doctype html><html lang="zh"><meta charset="utf-8"><title>Cyaim 演示授权中心</title>
    <body style="font-family:system-ui;max-width:640px;margin:48px auto;line-height:1.8">
    <h1>Cyaim 演示授权中心</h1>
    <ul>
      <li><a href="{{AuthConstants.Endpoints.AdminPanel}}">权限管理面板</a>（admin / Admin!123）</li>
      <li><a href="{{AuthConstants.Endpoints.Discovery}}">OIDC 发现文档</a></li>
      <li><a href="{{AuthConstants.Endpoints.Login}}">统一登录页</a></li>
    </ul>
    </body></html>
    """, "text/html; charset=utf-8")).AllowGuest();

// ---------- 幂等种子数据 ----------
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();

    await seeder.EnsureRoleAsync("admin",
        new[] { AuthConstants.AdminPermissions.All, "demo.**" },
        displayName: "系统管理员", isSystem: true);
    await seeder.EnsureRoleAsync("auditor",
        new[] { AuthConstants.AdminPermissions.Read, AuthConstants.AdminPermissions.ReadAudit },
        displayName: "审计员");
    await seeder.EnsureRoleAsync("order-viewer", new[] { "demo.order.read" }, displayName: "订单查看");
    await seeder.EnsureRoleAsync("order-admin", new[] { "demo.order.**", "demo.ws.**" },
        parentRoles: new[] { "order-viewer" }, displayName: "订单管理");

    await seeder.EnsureUserAsync("admin", "Admin!123", roles: new[] { "admin" }, displayName: "管理员");
    await seeder.EnsureUserAsync("alice", "alice123", roles: new[] { "order-admin" }, displayName: "Alice");
    await seeder.EnsureUserAsync("bob", "bob123", roles: new[] { "order-viewer" }, displayName: "Bob");

    // 管理面板（SPA，密码登录）
    await seeder.EnsureClientAsync("cyaim-admin-panel", null,
        new[] { AuthConstants.GrantTypes.Password, AuthConstants.GrantTypes.RefreshToken },
        allowedScopes: new[] { AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
        allowOfflineAccess: true, clientName: "权限管理面板");

    // 桌面客户端（WPF 示例，公共客户端）
    await seeder.EnsureClientAsync("wpf-client", null,
        new[] { AuthConstants.GrantTypes.Password, AuthConstants.GrantTypes.RefreshToken },
        allowedScopes: new[] { AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
        allowOfflineAccess: true, clientName: "WPF 桌面示例");

    // 浏览器应用（WASM 示例，授权码 + PKCE）
    await seeder.EnsureClientAsync("wasm-client", null,
        new[] { AuthConstants.GrantTypes.AuthorizationCode, AuthConstants.GrantTypes.RefreshToken },
        allowedScopes: new[] { AuthConstants.Scopes.OpenId, AuthConstants.Scopes.Profile, AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
        redirectUris: new[]
        {
            "http://localhost:5290/authentication/login-callback",
            "http://localhost:5290/callback",
        },
        postLogoutRedirectUris: new[] { "http://localhost:5290/" },
        allowOfflineAccess: true, clientName: "Blazor WASM 示例", requirePkce: true);

    // 服务间调用（机器客户端）
    await seeder.EnsureClientAsync("demo-m2m", "m2m-secret-please-change",
        new[] { AuthConstants.GrantTypes.ClientCredentials },
        allowedScopes: new[] { AuthConstants.Scopes.Permissions },
        permissions: new[] { "demo.order.read" },
        clientName: "演示服务客户端");

    await seeder.EnsurePermissionDefinitionsAsync(new (string, string?, string?)[]
    {
        ("demo.order.read", "查看订单", "订单"),
        ("demo.order.create", "创建订单", "订单"),
        ("demo.order.delete", "删除订单", "订单"),
        ("demo.ws.connect", "连接实时通道", "实时"),
        ("demo.ws.broadcast", "广播消息", "实时"),
    });
}

app.Run();
