# 桌面 / WASM / 控制台客户端

> 用 `Cyaim.Authentication.Client` SDK 在 WPF、Blazor WebAssembly、控制台等非浏览器托管环境完成统一登录、自动刷新、令牌缓存与本地权限门控。

`[文档中心](../README.md) / 指南`

本篇讲解 **客户端 SDK**（`Cyaim.Authentication.Client` 包，目标框架 `netstandard2.0` + `net8.0`，可用于 WPF/WinForms/WASM/控制台/服务）。它是纯 OAuth2/OIDC 客户端，只依赖 HTTP，不依赖授权服务器实现细节，因此也能对接任何标准 OIDC 提供方。授权服务器一侧的搭建见 [搭建授权中心与统一登录](./auth-server-sso.md)。

---

## 一、安装与核心类型

```bash
dotnet add package Cyaim.Authentication.Client
```

SDK 的所有能力集中在一个线程安全的 `CyaimAuthClient` 实例上，可跨 WPF/WASM/控制台/服务的整个进程生命周期复用（作为单例）。

构造函数（源码 `src/Cyaim.Authentication.Client/CyaimAuthClient.cs`）：

```csharp
public CyaimAuthClient(
    CyaimAuthClientOptions options,      // 必填，Authority 不能为空
    HttpClient? httpClient = null,       // 不传则内部自建并随 Dispose 释放
    ITokenCache? cache = null,           // 传入时构造即尝试从缓存恢复上次会话
    IAuthClock? clock = null)            // 默认系统时钟，测试可注入
```

配置项 `CyaimAuthClientOptions`（源码 `CyaimAuthClientOptions.cs`）：

| 属性 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `Authority` | `string` | `""`（必填） | 授权服务器地址，如 `https://auth.example.com` |
| `ClientId` | `string` | `""` | 客户端标识 |
| `ClientSecret` | `string?` | `null` | 机密客户端密钥；公共客户端（WASM/桌面）留空 |
| `Scopes` | `List<string>` | `["permissions", "offline_access"]` | 请求作用域：携带权限声明 + 签发刷新令牌 |
| `AutoRefresh` | `bool` | `true` | 访问令牌过期时是否自动用刷新令牌续期 |
| `RefreshSkew` | `TimeSpan` | `60s` | 提前刷新窗口：剩余有效期小于此值即视为过期 |
| `DiscoveryPath` | `string` | `/.well-known/openid-configuration` | 发现文档路径（相对 `Authority`） |

```csharp
using Cyaim.Authentication.Client;

var client = new CyaimAuthClient(new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "wpf-client",
    // Scopes 默认即 [permissions, offline_access]
});
```

> SDK 内部全部使用绝对 URL，不依赖 `HttpClient.BaseAddress`；传入自定义 `HttpClient` 时无需设置 `BaseAddress`。

---

## 二、三种登录流程

SDK 支持三种 OAuth2 授权类型，登录成功后令牌都存入 `CurrentToken` 并触发 `TokenChanged` 事件。授权服务器端点见 [OAuth2/OIDC 端点参考](../reference/server-endpoints.md)。

### 1. 资源所有者密码模式（桌面 / 受信客户端）

适合自建登录界面的桌面应用（授权服务器需为该客户端启用 `password` 授权）。

```csharp
public Task LoginWithPasswordAsync(string userName, string password, CancellationToken cancellationToken = default)
```

```csharp
try
{
    await client.LoginWithPasswordAsync("alice", "alice123");
}
catch (CyaimAuthException ex)
{
    // 协议错误：invalid_grant（用户名/密码错误）、unauthorized_client 等
    Console.WriteLine($"登录失败：{ex.Error} {ex.ErrorDescription}");
}
```

### 2. 客户端凭据模式（服务对服务 / 控制台 M2M）

无用户上下文，用 `ClientId` + `ClientSecret` 直接换令牌。适合后台服务、定时任务、控制台工具。

```csharp
public Task LoginWithClientCredentialsAsync(CancellationToken cancellationToken = default)
```

```csharp
var client = new CyaimAuthClient(new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "demo-m2m",
    ClientSecret = "m2m-secret-please-change",
    Scopes = new List<string> { "permissions" },   // M2M 通常不需要 offline_access
});

await client.LoginWithClientCredentialsAsync();
```

> 客户端凭据模式一般不签发刷新令牌；令牌过期后再次调用 `LoginWithClientCredentialsAsync()` 重新获取即可。

### 3. 授权码 + PKCE（浏览器 / 公共客户端）

公共客户端（无密钥的 WASM、桌面内嵌浏览器）应使用授权码 + PKCE。分两步：先跳转授权端点，回调后用授权码换令牌。

`Pkce` 工具类（源码 `Pkce.cs`）：

```csharp
public static string CreateCodeVerifier(int length = 64);          // 43-128 位随机串
public static string CreateCodeChallenge(string codeVerifier);     // Base64Url(SHA256(verifier))，method=S256
public static string BuildAuthorizeUrl(
    string authority, string clientId, string redirectUri,
    IEnumerable<string> scopes, string? state, string codeChallenge,
    IDictionary<string, string>? extraParams = null);
```

**第一步：生成 PKCE 参数并跳转**（`state` 与 `code_verifier` 需在回调前持久保存）：

```csharp
string verifier = Pkce.CreateCodeVerifier();
string challenge = Pkce.CreateCodeChallenge(verifier);
string state = Guid.NewGuid().ToString("N");

// 保存 verifier 与 state（WASM 用 sessionStorage，桌面用内存/本地文件）待回调校验

string url = Pkce.BuildAuthorizeUrl(
    authority: "http://127.0.0.1:5299",
    clientId: "wasm-client",
    redirectUri: "http://localhost:5290/callback",
    scopes: new[] { "permissions", "offline_access" },
    state: state,
    codeChallenge: challenge);
// 浏览器整页跳转到 url（会落到授权服务器 /connect/authorize → /account/login）
```

**第二步：回调页用授权码换令牌**（校验 `state`，取回 `code_verifier`）：

```csharp
public Task ExchangeAuthorizationCodeAsync(
    string code, string redirectUri, string codeVerifier,
    CancellationToken cancellationToken = default)
```

```csharp
// redirectUri 必须与第一步完全一致
await client.ExchangeAuthorizationCodeAsync(code, "http://localhost:5290/callback", verifier);
```

> 服务器仅支持 `code_challenge_method=S256`（`Pkce.CreateCodeChallenge` 恒用 S256），不支持 `plain`。

---

## 三、自动刷新与获取有效令牌

`GetAccessTokenAsync` 是取令牌的**唯一入口**：未过期直接返回，过期且 `AutoRefresh=true` 时先刷新再返回。

```csharp
public Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default);
public Task<bool> RefreshAsync(CancellationToken cancellationToken = default);
```

```csharp
try
{
    string accessToken = await client.GetAccessTokenAsync();
    // 用 accessToken 调用受保护 API
}
catch (InvalidOperationException)
{
    // 未登录，或令牌过期且无法自动刷新 —— 引导用户重新登录
}
```

行为要点（源码 `GetAccessTokenAsync` / `RefreshCoreAsync`）：

- 令牌有效走无锁快路径，直接返回，不进信号量，适合高频调用。
- 刷新令牌被服务器拒绝（`invalid_grant`）时，SDK 清空本地令牌、触发 `SessionExpired` 事件，此时 `GetAccessTokenAsync` 抛 `InvalidOperationException`（消息「登录会话已过期，请重新登录」）。
- `RefreshAsync()` 返回 `bool`：无刷新令牌或刷新被拒返回 `false`，成功返回 `true`。手动调用一般不需要——交给 `GetAccessTokenAsync` 与消息处理器自动完成。

事件（源码 `TokenChanged` / `SessionExpired`）：

```csharp
client.TokenChanged  += (_, _) => { /* 登录、刷新、登出后触发，可刷新 UI 登录状态 */ };
client.SessionExpired += (_, _) => { /* 刷新令牌被拒，应引导重新登录 */ };
```

> 事件可能在任意线程触发（如后台刷新线程）。在 UI 应用里务必**切回 UI 线程**再更新界面，见下文 WPF 小节。

---

## 四、令牌缓存（重启免登录）

缓存实现 `ITokenCache`（源码 `ITokenCache.cs`），构造 `CyaimAuthClient` 时传入即在构造函数里尝试恢复上次会话：

```csharp
public interface ITokenCache
{
    TokenSet? Load();          // 无缓存或损坏返回 null
    void Save(TokenSet? tokenSet);   // 传 null 表示清除（登出）
}
```

### InMemoryTokenCache（进程内，不持久化）

进程退出即失效，适合 WASM（刷新页面即重登）、控制台、测试：

```csharp
var client = new CyaimAuthClient(options, cache: new InMemoryTokenCache());
```

### FileTokenCache + DPAPI 加密（桌面持久化）

`FileTokenCache`（源码 `FileTokenCache.cs`）把 `TokenSet` 序列化到指定文件，写入原子（临时文件 + 替换）。可选 `protect`/`unprotect` 钩子注入平台加密：

```csharp
public FileTokenCache(
    string path,
    Func<byte[], byte[]>? protect = null,     // 写入前加密
    Func<byte[], byte[]>? unprotect = null)   // 读取后解密（须与 protect 配对）
```

Windows 下用 DPAPI（`ProtectedData`，当前用户范围）加密——文件只有当前 Windows 用户能解密（源码 `samples/Sample.Wpf/App.xaml.cs`）：

```csharp
using System.Security.Cryptography;   // System.Security.Cryptography.ProtectedData 包

string cachePath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
    "MyApp", "token.json");

var cache = new FileTokenCache(
    cachePath,
    protect:   data => ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser),
    unprotect: data => ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser));

var client = new CyaimAuthClient(new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "wpf-client",
}, cache: cache);

// 构造后 client.IsLoggedIn 即反映缓存中是否有令牌
if (client.IsLoggedIn)
{
    try { await client.GetAccessTokenAsync(); /* 有效或可刷新 → 免登录 */ }
    catch (InvalidOperationException) { /* 失效 → 走登录界面 */ }
}
```

> DPAPI 仅在 Windows 可用（需引用 `System.Security.Cryptography.ProtectedData` NuGet 包）。跨平台桌面可换用其它对称加密实现 `protect`/`unprotect`；不传钩子则以明文 JSON 落盘，仅建议用于开发。

`TokenSet` 结构（源码 `TokenSet.cs`）：`AccessToken`、`RefreshToken?`、`ExpiresAt`（UTC）、`Scopes?`。

---

## 五、本地权限判断门控 UI

登录后可把权限加载到本地，用 `HasPermission` **离线**判断（支持通配符与拒绝优先，与服务端同一套语义，见 [权限代码语法参考](../reference/permission-codes.md)），用来启停按钮/菜单。两种加载方式：

```csharp
public Task LoadPermissionsAsync(CancellationToken cancellationToken = default);   // 调 UserInfo 端点取 permissions 数组
public bool LoadPermissionsFromToken();                                            // 从访问令牌 perm 声明本地解析，不联网
public bool HasPermission(string code);                                            // 未加载时返回 false
public IReadOnlyList<string>? GrantedPermissions { get; }                          // 已加载的授予代码
```

```csharp
await client.LoadPermissionsAsync();   // 联网：从 UserInfo 端点加载
// 或离线：client.LoadPermissionsFromToken();（需令牌签发时启用 IncludePermissionsInToken）

readButton.IsEnabled   = client.HasPermission("demo.order.read");
deleteButton.IsEnabled = client.HasPermission("demo.order.delete");
```

推荐做法：优先 `LoadPermissionsAsync()`，联网失败时退化到 `LoadPermissionsFromToken()`（源码 `samples/Sample.Wpf/MainWindow.xaml.cs`）：

```csharp
try
{
    await client.LoadPermissionsAsync();
}
catch (Exception)   // CyaimAuthException / HttpRequestException
{
    client.LoadPermissionsFromToken();   // 退化：从令牌离线解析权限
}
```

> **本地权限判断只用于 UI 体验（灰掉不可用按钮）**，不是安全边界。真正的授权判断永远由资源服务器在服务端执行——见 [保护 ASP.NET Core API](./protect-aspnetcore.md)。

---

## 六、自动附带令牌调用 API

`CyaimAuthHttpMessageHandler`（源码 `CyaimAuthHttpMessageHandler.cs`）是一个 `DelegatingHandler`：请求前自动附加 `Authorization: Bearer <token>`，收到 401 且能刷新时刷新一次并重试原请求。

```csharp
public CyaimAuthHttpMessageHandler(CyaimAuthClient client);
public CyaimAuthHttpMessageHandler(CyaimAuthClient client, HttpMessageHandler innerHandler);
```

```csharp
var api = new HttpClient(new CyaimAuthHttpMessageHandler(client, new HttpClientHandler()));

// 之后所有请求自动带上 Bearer 令牌，无需手动取令牌
HttpResponseMessage resp = await api.GetAsync("http://127.0.0.1:5298/api/orders");
```

行为要点：

- 请求方已显式设置 `Authorization` 头时不覆盖。
- 未登录或取不到有效令牌时按匿名请求发出，由服务端返回 401。
- 401 重试用 `RefreshIfCurrentAsync` 合并并发刷新（避免刷新惊群与刷新令牌连环轮换）；刷新仍失败则原样返回 401。

在 DI 容器里也可注册为带处理器的具名/单例 `HttpClient`（WASM 示例即如此，见下文）。

---

## 七、WPF 桌面要点

参考实现：`samples/Sample.Wpf`（`net9.0-windows`，密码模式 + DPAPI 缓存）。

- **共享单例**：在 `App` 里持有一个静态 `CyaimAuthClient`，登录窗与主窗共用（源码 `App.xaml.cs`）。授权服务器地址可编辑时，地址变化需 `Dispose` 旧实例重建。
- **静默恢复**：启动时若 `IsLoggedIn` 为真，`await GetAccessTokenAsync()` 验证令牌有效（或可刷新）即跳过登录窗。
- **事件回 UI 线程**：`TokenChanged`/`SessionExpired` 可能来自后台线程，更新界面前用 `Dispatcher.Invoke`（源码 `MainWindow.xaml.cs`）：

```csharp
_client.SessionExpired += (_, _) => Dispatcher.Invoke(() =>
{
    MessageBox.Show("登录会话已过期，请重新登录。");
    // 回到登录窗
});
```

- **门控 + 禁用原因**：`HasPermission` 启停按钮，把原因写进 `ToolTip`，并 `ToolTipService.SetShowOnDisabled(button, true)` 让禁用态也显示提示。
- **异步不阻塞**：登录/调用 API 全程 `async/await`，`async void` 仅用于事件处理器。

---

## 八、Blazor WebAssembly 要点

参考实现：`samples/Sample.Wasm`（`net9.0`，授权码 + PKCE，固定端口 5290）。

- **DI 注册**（源码 `Program.cs`）：`CyaimAuthClientOptions`、`CyaimAuthClient`（用 `InMemoryTokenCache`）、以及 `CyaimAuthHttpMessageHandler` 包装的 `HttpClient` 都注册为单例：

```csharp
var authOptions = new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "wasm-client",
    Scopes = new List<string> { "permissions", "offline_access" },
};
builder.Services.AddSingleton(authOptions);
builder.Services.AddSingleton(sp => new CyaimAuthClient(authOptions, cache: new InMemoryTokenCache()));
builder.Services.AddSingleton(sp => new HttpClient(
    new CyaimAuthHttpMessageHandler(sp.GetRequiredService<CyaimAuthClient>())
    {
        InnerHandler = new HttpClientHandler(),
    }));
```

- **PKCE 参数存 sessionStorage**：跳转前把 `code_verifier` 与 `state` 写入浏览器 `sessionStorage`，回调页取回校验（源码 `Pages/Home.razor` / `Pages/Callback.razor`）：

```csharp
// 发起登录（Home.razor）
string verifier = Pkce.CreateCodeVerifier();
string state = Guid.NewGuid().ToString("N");
await JS.InvokeVoidAsync("sessionStorage.setItem", "pkce_verifier", verifier);
await JS.InvokeVoidAsync("sessionStorage.setItem", "pkce_state", state);
string origin = new Uri(Nav.BaseUri).GetLeftPart(UriPartial.Authority);
string url = Pkce.BuildAuthorizeUrl(AuthOptions.Authority, AuthOptions.ClientId,
    origin + "/callback", AuthOptions.Scopes, state, Pkce.CreateCodeChallenge(verifier));
Nav.NavigateTo(url, forceLoad: true);   // 整页跳转
```

```csharp
// 回调（Callback.razor）：校验 state → 换令牌 → 加载权限
if (!string.Equals(state, expectedState, StringComparison.Ordinal)) { /* 阻止登录 */ }
await Auth.ExchangeAuthorizationCodeAsync(code, origin + "/callback", verifier);
await Auth.LoadPermissionsAsync();
Nav.NavigateTo("/");
```

- **注销**：`LogoutAsync()` 吊销并清本地令牌后，再整页跳到授权服务器 `/account/logout?post_logout_redirect_uri=...` 结束 SSO 会话。
- **CORS**：WASM 在浏览器里跨域调用 `/connect/token`、`/connect/userinfo`、`/connect/revocation` 与资源 API，需要授权服务器与资源服务器允许 WASM 来源（如 `http://localhost:5290`）。整页跳转的 `/connect/authorize`、`/account/login` 不受 CORS 限制。详见 `samples/Sample.Wasm/README.md`。
- **回调地址固定**：授权服务器种子里 `wasm-client` 的 `redirect_uri` 是 `http://localhost:5290/callback`，故 WASM 应用端口必须固定 5290。

---

## 九、控制台 / 后台服务

控制台工具与后台服务通常用客户端凭据模式 + `InMemoryTokenCache`，配合消息处理器调用受保护 API：

```csharp
using var authClient = new CyaimAuthClient(new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "demo-m2m",
    ClientSecret = "m2m-secret-please-change",
    Scopes = new List<string> { "permissions" },
}, cache: new InMemoryTokenCache());

await authClient.LoginWithClientCredentialsAsync();

using var api = new HttpClient(new CyaimAuthHttpMessageHandler(authClient, new HttpClientHandler()));
string orders = await api.GetStringAsync("http://127.0.0.1:5298/api/orders");
Console.WriteLine(orders);
```

`CyaimAuthClient` 实现 `IDisposable`；自建 `HttpClient` 会随 `Dispose` 释放，外部传入的不释放。

---

## 相关文档

- [示例总览](../samples.md) —— 四个可运行示例的启动步骤与演示账户
- [搭建授权中心与统一登录](./auth-server-sso.md) —— 客户端对接的授权服务器一侧
- [保护 ASP.NET Core API](./protect-aspnetcore.md) —— 资源服务器端的权限校验
- [OAuth2/OIDC 端点参考](../reference/server-endpoints.md) —— 令牌/授权/UserInfo 等端点细节
- [公开 API 参考](../reference/api.md) —— `CyaimAuthClient` 等类型完整成员
- [权限代码语法参考](../reference/permission-codes.md) —— 通配符与拒绝优先语义
- [快速上手](../getting-started.md)
</content>
</invoke>
