// Sample.Wasm —— Blazor WebAssembly 独立应用示例：
// 使用 Cyaim.Authentication.Client SDK 在浏览器中完成授权码 + PKCE 统一登录。
using Cyaim.Authentication.Client;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Sample.Wasm;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// 客户端 SDK 配置：公共客户端（无密钥），授权码 + PKCE
var authOptions = new CyaimAuthClientOptions
{
    Authority = "http://127.0.0.1:5299",
    ClientId = "wasm-client",
    Scopes = new List<string> { "permissions", "offline_access" },
};
builder.Services.AddSingleton(authOptions);

// CyaimAuthClient 单例（InMemoryTokenCache：令牌保存在内存中，刷新页面后需重新登录）
builder.Services.AddSingleton(sp => new CyaimAuthClient(authOptions, cache: new InMemoryTokenCache()));

// 调用资源 API 用的 HttpClient：CyaimAuthHttpMessageHandler 自动附加 Bearer 令牌并在 401 时刷新重试
builder.Services.AddSingleton(sp => new HttpClient(
    new CyaimAuthHttpMessageHandler(sp.GetRequiredService<CyaimAuthClient>())
    {
        InnerHandler = new HttpClientHandler(),
    }));

await builder.Build().RunAsync();
