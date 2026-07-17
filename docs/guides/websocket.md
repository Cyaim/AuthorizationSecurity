# WebSocket 鉴权

> 在握手阶段用权限中间件拦截连接，在消息循环里做细粒度权限判断。

[文档中心](../README.md) / 指南（Guides）

WebSocket 的鉴权分两层：**握手（HTTP 升级请求）**由权限中间件统一拦截，和普通端点一样标注 `.RequirePermission(...)`；**连接建立后**的每条消息可用命令式 API 做更细的权限判断。本指南用 `samples/Sample.WebApi` 的 `/ws/echo` 给出完整可运行示例。

---

## 握手阶段鉴权

WebSocket 连接始于一个普通 HTTP GET 升级请求，因此权限中间件能像拦截任何端点一样拦截它。前提：先 `app.UseWebSockets()`，再 `app.UseCyaimAuthentication()`，然后给 WebSocket 端点标注所需权限。

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "cyaim-demo";
    o.Audience = "demo-api";
    o.HmacSigningKey = "至少32字节的对称签名密钥................";
    // AllowTokenFromQuery 默认 true——浏览器 WebSocket 无法设自定义头，需靠 ?access_token=
}).AddInMemoryStore();

var app = builder.Build();

app.UseWebSockets();
app.UseCyaimAuthentication();

app.Map("/ws/echo", async (HttpContext context) =>
{
    // 走到这里，握手已被中间件校验通过 demo.ws.connect
    // ...见下文消息循环
}).RequirePermission("demo.ws.connect");   // 握手所需权限

app.Run();
```

握手请求缺少 `demo.ws.connect` 权限时，中间件在 WebSocket 升级发生前就返回 HTTP 拒绝响应（403/401），连接不会建立。

### 令牌怎么带

浏览器原生 `WebSocket` API **不能自定义请求头**，所以无法用 `Authorization: Bearer`。框架默认开启从查询字符串取令牌（`AllowTokenFromQuery = true`，参数名 `access_token`），正是为此场景：

```javascript
// 浏览器客户端：令牌放查询字符串
const token = "eyJhbGciOi...";
const ws = new WebSocket(`ws://localhost:5000/ws/echo?access_token=${encodeURIComponent(token)}`);
```

非浏览器客户端（.NET `ClientWebSocket`、`wscat` 等）能设请求头时，仍推荐用 `Authorization` 头：

```csharp
using System.Net.WebSockets;

var ws = new ClientWebSocket();
ws.Options.SetRequestHeader("Authorization", "Bearer eyJhbGciOi...");
await ws.ConnectAsync(new Uri("ws://localhost:5000/ws/echo"), CancellationToken.None);
```

```bash
# wscat：用查询字符串最省事
wscat -c "ws://localhost:5000/ws/echo?access_token=<token>"
```

令牌来源的完整配置（头名、查询参数名、是否允许 Cookie）见 [保护 ASP.NET Core API · 配置令牌来源](protect-aspnetcore.md#配置令牌来源)。

> 安全提示：查询字符串会出现在服务器访问日志与代理日志里。生产环境优先用短时效访问令牌，并对 WebSocket 走 `wss://`（TLS）。若不需要浏览器场景，可将 `AllowTokenFromQuery` 设为 `false`。

---

## 消息级细粒度判断

握手权限（如 `demo.ws.connect`）只决定"能否建立连接"。连接内不同指令可能需要不同权限——用 `HttpContext.HasPermissionAsync(code)` 在消息循环里逐条判断。`HttpContext` 在整个 WebSocket 生命周期内有效，主体已由中间件解析并缓存。

```csharp
// 收到 /broadcast 指令时，额外要求 demo.ws.broadcast
if (text.StartsWith("/broadcast", StringComparison.OrdinalIgnoreCase) &&
    !await context.HasPermissionAsync("demo.ws.broadcast"))
{
    await Send(ws, "错误：缺少 demo.ws.broadcast 权限");
    continue;   // 拒绝该指令，但不断开连接
}
```

需要拒绝原因用于诊断时，改用 `CheckPermissionAsync` 拿完整 `AuthorizationDecision`：

```csharp
AuthorizationDecision d = await context.CheckPermissionAsync("demo.ws.broadcast");
if (!d.IsGranted)
{
    await Send(ws, $"拒绝：{d.Reason}");   // 例如 NoMatchingGrant / DeniedByRule
    continue;
}
```

`GetAuthSubject()` 可随时取当前主体信息（Id、Name、Roles 等），用于在消息里标注发送者身份。这些扩展的完整签名见 [保护 ASP.NET Core API · 命令式权限判断](protect-aspnetcore.md#命令式权限判断)。

> 注意：权限判断读取的是主体建立连接时解析出的权限快照。若需要在长连接期间实时反映用户权限被撤销，应结合较短的令牌有效期或在业务层加入重新校验/主动断开逻辑。

---

## 完整可运行示例

以下是 `samples/Sample.WebApi/Program.cs` 中 `/ws/echo` 端点的完整实现：握手校验 `demo.ws.connect`，回显消息，并对 `/broadcast` 指令做消息级 `demo.ws.broadcast` 校验。

```csharp
using System.Net.WebSockets;
using System.Text;

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
```

### 端到端试跑

```bash
cd samples/Sample.WebApi
dotnet run
```

启动时控制台会打印 alice / bob / carol 三个演示用户的令牌。示例中角色权限（见 `Program.cs` 种子数据）：

- `alice` 属 `order-admin`，拥有 `demo.ws.**`——握手与广播都能过。
- `bob` 属 `order-viewer`，只有 `demo.order.read`——握手就会被拒（缺 `demo.ws.connect`）。

```bash
# alice：握手成功，普通消息回显，/broadcast 也被放行
wscat -c "ws://localhost:5000/ws/echo?access_token=<alice-token>"
> hello
< [Alice 管理员] hello
> /broadcast 大家好
< [Alice 管理员] /broadcast 大家好

# 用只有 order-viewer 的 bob：握手直接被拒（HTTP 403），连接建立不了
wscat -c "ws://localhost:5000/ws/echo?access_token=<bob-token>"
```

要观察"握手通过但广播被拒"的效果，可给某个用户授予 `demo.ws.connect` 却不授予 `demo.ws.broadcast`，再发送 `/broadcast` 指令即会收到"缺少 demo.ws.broadcast 权限"。

---

## 相关文档

- [保护 ASP.NET Core API](protect-aspnetcore.md) —— 中间件接入、标注端点、命令式判断、令牌来源
- [权限模型](../concepts/permission-model.md) —— 权限代码、通配符（`demo.ws.**`）、拒绝优先
- [令牌与会话](../concepts/tokens-and-sessions.md) —— JWT 声明、有效期、刷新
- [配置参考](../reference/configuration.md) —— `AllowTokenFromQuery`、`QueryTokenParameter` 等
- [判断原因与错误码](../reference/decisions-and-errors.md) —— `AuthorizationReason` 取值
- [示例总览](../samples.md) —— 四个可运行示例的启动命令与演示账户
