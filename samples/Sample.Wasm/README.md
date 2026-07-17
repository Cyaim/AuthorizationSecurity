# Sample.Wasm —— Blazor WebAssembly 授权码 + PKCE 示例

演示 `Cyaim.Authentication.Client` SDK 在浏览器（Blazor WebAssembly 独立应用）中完成
授权码 + PKCE 统一登录，并携带令牌调用受权限保护的资源 API。

## 流程概览

1. 首页点击「登录」：`Pkce.CreateCodeVerifier()` 生成 code_verifier 存入 sessionStorage，
   `Pkce.BuildAuthorizeUrl(...)` 构建授权地址后整页跳转到授权服务器 `/connect/authorize`。
2. 授权服务器登录页（`/account/login`，SSO Cookie）认证后 302 回 `http://localhost:5290/callback?code=...&state=...`。
3. `/callback` 页校验 state、取回 verifier，调用 `ExchangeAuthorizationCodeAsync(code, redirectUri, verifier)`
   换取令牌，再 `LoadPermissionsAsync()` 加载权限后跳回首页。
4. 首页显示用户信息（`GetUserInfoAsync`）与权限列表（`GrantedPermissions`）；
   「读取订单」按钮按 `HasPermission("demo.order.read")` 启停，通过
   `CyaimAuthHttpMessageHandler` 包装的 `HttpClient`（自动附加 Bearer、401 时刷新重试）调用资源 API。
5. 「注销」：`LogoutAsync()`（吊销刷新令牌并清空本地令牌）后跳转
   `/account/logout?post_logout_redirect_uri=...` 结束授权服务器 SSO 会话。

## 启动顺序

三个终端依次启动（端口必须与下方一致）：

```bash
# 1. 授权中心（种子里 wasm-client 的 redirect_uri 为 http://localhost:5290/callback）
dotnet run --project samples/Sample.AuthServer --urls http://127.0.0.1:5299

# 2. 资源 API
dotnet run --project samples/Sample.WebApi --urls http://127.0.0.1:5298

# 3. 本应用（launchSettings.json 已固定端口 5290）
dotnet run --project samples/Sample.Wasm
```

浏览器访问 http://localhost:5290 ，点击「登录」，使用 AuthServer 种子用户
（如 alice / 其在 Sample.AuthServer/Program.cs 中的种子密码）完成登录。

> 端口 5290 必须固定：授权服务器种子数据中 `wasm-client` 的回调地址是
> `http://localhost:5290/callback`，注销回跳地址是 `http://localhost:5290/`。

## CORS 说明（重要）

本示例演示的是同一台机器、不同端口的场景 —— 对浏览器而言
`http://localhost:5290`、`http://127.0.0.1:5299`、`http://127.0.0.1:5298` 是**三个不同的源**，
浏览器会按同源策略拦截跨域的 XHR/fetch 请求：

- **授权服务器（Sample.AuthServer）**：`/connect/authorize` 与 `/account/login` 走的是整页跳转，
  不受 CORS 限制；但 `/connect/token`（换令牌、刷新令牌）、`/connect/userinfo`、`/connect/revocation`
  是由 WASM 在浏览器里跨域调用的，**需要授权服务器允许来源 `http://localhost:5290`**。
- **资源 API（Sample.WebApi）**：「读取订单」按钮跨域调用 `/api/orders`，同样需要允许该来源。

Sample.AuthServer 与 Sample.WebApi 属于已完成的独立示例，本示例不改动它们。
如需完整体验浏览器端流程，可自行在这两个示例的 `Program.cs` 中加入 CORS（开发环境任意来源示意）：

```csharp
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));
// ...
app.UseCors(); // 放在 UseCyaimAuthentication() 之前
```

生产环境请用 `WithOrigins("https://你的前端域名")` 精确限定来源，不要使用任意来源。

## 关键代码位置

- `Program.cs`：注册 `CyaimAuthClient` 单例（Authority `http://127.0.0.1:5299`、
  clientId `wasm-client`、scopes `[permissions, offline_access]`、`InMemoryTokenCache`）
  与 `CyaimAuthHttpMessageHandler` 包装的 `HttpClient`。
- `Pages/Home.razor`：登录发起、用户信息 / 权限展示、按权限启停的 API 调用、注销。
- `Pages/Callback.razor`：授权码回调处理（state 校验 + 换令牌 + 加载权限）。

> 提示：本示例使用 `InMemoryTokenCache`，刷新页面后令牌即丢失需重新登录；
> 若授权服务器的 SSO Cookie 仍有效，重新登录不需再次输入密码。
