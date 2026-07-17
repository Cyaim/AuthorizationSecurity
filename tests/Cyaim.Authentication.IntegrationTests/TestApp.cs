using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Core;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// 全栈集成测试宿主：TestServer 内存宿主 + 授权服务器 + 管理面板 + 测试资源端点 + 种子数据。
    /// 每个测试实例独立创建，互不共享状态。
    /// </summary>
    public sealed class TestApp : IAsyncDisposable
    {
        /// <summary>HMAC 签名密钥（32 字节以上）</summary>
        public const string SigningKey = "integration-test-signing-key-32bytes!!";

        /// <summary>宿主应用</summary>
        public WebApplication App { get; }

        /// <summary>内存 HTTP 客户端（不跟随重定向、不管理 Cookie）</summary>
        public HttpClient Client { get; }

        /// <summary>DI 容器</summary>
        public IServiceProvider Services => App.Services;

        /// <summary>内存测试服务器</summary>
        public TestServer Server => App.GetTestServer();

        private TestApp(WebApplication app, HttpClient client)
        {
            App = app;
            Client = client;
        }

        /// <summary>
        /// 构建并启动测试宿主：完整组装权限框架、授权服务器、管理面板与测试资源端点，并写入种子数据。
        /// </summary>
        public static async Task<TestApp> CreateAsync()
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            builder.Logging.ClearProviders();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);

            builder.Services.AddCyaimAuthentication(o =>
            {
                o.Issuer = "cyaim-it";
                o.Audience = "it-api";
                o.HmacSigningKey = SigningKey;
            }).AddInMemoryStore()
              .AddPolicy("even", ctx => true)
              .AddPolicy("odd", ctx => false);

            builder.Services.AddCyaimAuthServer(o => o.ServerName = "IT Auth");
            builder.Services.AddCyaimAuthAdminPanel();

            WebApplication app = builder.Build();

            app.UseWebSockets();
            app.UseCyaimAuthentication();
            app.MapCyaimAuthServer();
            app.MapCyaimAuthAdmin();

            // ---------- 测试资源端点 ----------
            app.MapGet("/t/read", () => Results.Text("read-ok")).RequirePermission("demo.order.read");
            app.MapDelete("/t/del", () => Results.Text("del-ok")).RequirePermission("demo.order.delete");
            app.MapGet("/t/all", () => Results.Text("all-ok")).RequireAllPermissions("demo.order.read", "demo.order.create");
            app.MapGet("/t/open", () => Results.Text("open-ok")).AllowGuest();
            app.MapGet("/t/authed", () => Results.Text("authed-ok")).RequirePermission();
            app.MapGet("/t/policy", () => Results.Text("policy-ok"))
                .RequirePermission("demo.order.read").RequireAuthPolicy("even");
            app.MapGet("/t/policy-odd", () => Results.Text("policy-odd-ok"))
                .RequirePermission("demo.order.read").RequireAuthPolicy("odd");
            app.Map("/t/ws", (Delegate)HandleWebSocketEchoAsync).RequirePermission("demo.ws.connect");

            await SeedAsync(app.Services);

            await app.StartAsync();
            return new TestApp(app, app.GetTestClient());
        }

        /// <summary>
        /// WebSocket 回显端点：握手鉴权由权限中间件完成（demo.ws.connect）。
        /// </summary>
        private static async Task HandleWebSocketEchoAsync(HttpContext context)
        {
            if (!context.WebSockets.IsWebSocketRequest)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            using WebSocket ws = await context.WebSockets.AcceptWebSocketAsync();
            byte[] buffer = new byte[4096];
            while (ws.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), context.RequestAborted);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", context.RequestAborted);
                    break;
                }

                await ws.SendAsync(
                    new ArraySegment<byte>(buffer, 0, result.Count),
                    result.MessageType, result.EndOfMessage, context.RequestAborted);
            }
        }

        /// <summary>
        /// 幂等种子数据（角色层级、拒绝优先、三类客户端），与 Sample.AuthServer 布局一致。
        /// </summary>
        private static async Task SeedAsync(IServiceProvider services)
        {
            using IServiceScope scope = services.CreateScope();
            AuthDataSeeder seeder = scope.ServiceProvider.GetRequiredService<AuthDataSeeder>();

            await seeder.EnsureRoleAsync("admin",
                new[] { AuthConstants.AdminPermissions.All, "demo.**" },
                displayName: "系统管理员", isSystem: true);
            await seeder.EnsureRoleAsync("order-viewer", new[] { "demo.order.read" }, displayName: "订单查看");
            await seeder.EnsureRoleAsync("order-admin", new[] { "demo.order.**", "demo.ws.**" },
                parentRoles: new[] { "order-viewer" }, displayName: "订单管理");
            await seeder.EnsureRoleAsync("order-admin-restricted",
                permissions: Array.Empty<string>(),
                parentRoles: new[] { "order-admin" },
                deniedPermissions: new[] { "demo.order.delete" },
                displayName: "受限订单管理");

            await seeder.EnsureUserAsync("admin", "Admin!123", roles: new[] { "admin" }, displayName: "管理员");
            await seeder.EnsureUserAsync("alice", "alice123", roles: new[] { "order-admin" }, displayName: "Alice");
            await seeder.EnsureUserAsync("bob", "bob123", roles: new[] { "order-viewer" }, displayName: "Bob");
            await seeder.EnsureUserAsync("carol", "carol123", roles: new[] { "order-admin-restricted" }, displayName: "Carol");
            await seeder.EnsureUserAsync("dave", "dave123", roles: new[] { "order-viewer" }, displayName: "Dave");

            // 密码模式客户端（公共客户端）
            await seeder.EnsureClientAsync("panel", null,
                new[] { AuthConstants.GrantTypes.Password, AuthConstants.GrantTypes.RefreshToken },
                allowedScopes: new[] { AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess },
                allowOfflineAccess: true, clientName: "测试面板");

            // 授权码 + PKCE 客户端
            await seeder.EnsureClientAsync("web", null,
                new[] { AuthConstants.GrantTypes.AuthorizationCode, AuthConstants.GrantTypes.RefreshToken },
                allowedScopes: new[]
                {
                    AuthConstants.Scopes.OpenId, AuthConstants.Scopes.Profile,
                    AuthConstants.Scopes.Permissions, AuthConstants.Scopes.OfflineAccess,
                },
                redirectUris: new[] { "http://localhost/callback" },
                allowOfflineAccess: true, clientName: "测试Web", requirePkce: true);

            // 机器客户端
            await seeder.EnsureClientAsync("m2m", "m2m-secret",
                new[] { AuthConstants.GrantTypes.ClientCredentials },
                allowedScopes: new[] { AuthConstants.Scopes.Permissions },
                permissions: new[] { "demo.order.read" },
                clientName: "测试机器客户端");
        }

        // ---------------------------------------------------------------- HTTP 帮助方法

        /// <summary>
        /// POST 表单（可选 Basic 客户端认证）。
        /// </summary>
        public async Task<HttpResponseMessage> PostFormAsync(
            string path, Dictionary<string, string> form, (string ClientId, string Secret)? basic = null)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new FormUrlEncodedContent(form),
            };
            if (basic != null)
            {
                string raw = Uri.EscapeDataString(basic.Value.ClientId) + ":" + Uri.EscapeDataString(basic.Value.Secret);
                request.Headers.Authorization = new AuthenticationHeaderValue(
                    "Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
            }
            return await Client.SendAsync(request);
        }

        /// <summary>
        /// 密码模式取令牌，断言前请自行检查状态码；成功返回解析后的 JSON。
        /// </summary>
        public async Task<HttpResponseMessage> PasswordTokenResponseAsync(
            string clientId, string user, string pass, string scope = "permissions offline_access")
        {
            return await PostFormAsync(AuthConstants.Endpoints.Token, new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = clientId,
                ["username"] = user,
                ["password"] = pass,
                ["scope"] = scope,
            });
        }

        /// <summary>
        /// 密码模式取令牌（要求成功），返回令牌响应 JSON。
        /// </summary>
        public async Task<JsonElement> PasswordTokenAsync(
            string clientId, string user, string pass, string scope = "permissions offline_access")
        {
            using HttpResponseMessage response = await PasswordTokenResponseAsync(clientId, user, pass, scope);
            JsonElement json = await ReadJsonAsync(response);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"密码模式取令牌失败 {(int)response.StatusCode}: {json.GetRawText()}");
            }
            return json;
        }

        /// <summary>
        /// 密码模式取访问令牌（要求成功）。
        /// </summary>
        public async Task<string> PasswordAccessTokenAsync(
            string clientId, string user, string pass, string scope = "permissions offline_access")
        {
            JsonElement json = await PasswordTokenAsync(clientId, user, pass, scope);
            return json.GetProperty("access_token").GetString()!;
        }

        /// <summary>
        /// 携带 Bearer 令牌 GET。
        /// </summary>
        public Task<HttpResponseMessage> AuthGetAsync(string path, string? token) =>
            AuthSendAsync(HttpMethod.Get, path, token);

        /// <summary>
        /// 携带 Bearer 令牌发送任意方法请求。
        /// </summary>
        public async Task<HttpResponseMessage> AuthSendAsync(
            HttpMethod method, string path, string? token, HttpContent? content = null)
        {
            using var request = new HttpRequestMessage(method, path) { Content = content };
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
            return await Client.SendAsync(request);
        }

        /// <summary>
        /// 携带 Bearer 令牌发送 JSON 请求体。
        /// </summary>
        public Task<HttpResponseMessage> AuthSendJsonAsync(HttpMethod method, string path, string token, object body)
        {
            var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            return AuthSendAsync(method, path, token, content);
        }

        /// <summary>
        /// 解析响应 JSON（返回可脱离响应生命周期的克隆元素）。
        /// </summary>
        public static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
        {
            string body = await response.Content.ReadAsStringAsync();
            using JsonDocument document = JsonDocument.Parse(body);
            return document.RootElement.Clone();
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }
}
