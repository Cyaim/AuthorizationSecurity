using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Windows;
using Cyaim.Authentication.Client;

namespace Sample.Wpf;

/// <summary>
/// WPF 桌面客户端示例入口。
/// 持有全应用共享的 <see cref="CyaimAuthClient"/> 单例，
/// 令牌通过 <see cref="FileTokenCache"/> + Windows DPAPI 加密持久化到本地，
/// 重启应用时若缓存令牌仍有效（或可刷新）则跳过登录直接进入主窗口。
/// </summary>
public partial class App : Application
{
    /// <summary>授权服务器默认地址（对应 Sample.AuthServer --urls http://127.0.0.1:5299）</summary>
    public const string DefaultAuthority = "http://127.0.0.1:5299";

    /// <summary>全应用共享的认证客户端单例（在 <see cref="InitializeClient"/> 后非空）</summary>
    public static CyaimAuthClient AuthClient { get; private set; } = null!;

    /// <summary>令牌缓存文件路径：%LOCALAPPDATA%/CyaimSample/token.json（DPAPI 加密，非明文）</summary>
    private static string TokenCachePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CyaimSample", "token.json");

    /// <summary>
    /// （重新）创建认证客户端。登录窗允许修改服务器地址，地址变化时需要重建客户端。
    /// </summary>
    /// <param name="authority">授权服务器地址</param>
    public static void InitializeClient(string authority)
    {
        AuthClient?.Dispose();

        // DPAPI（当前用户范围）加密令牌缓存：其他用户 / 其他机器无法解密该文件
        var cache = new FileTokenCache(
            TokenCachePath,
            protect: data => ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser),
            unprotect: data => ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser));

        AuthClient = new CyaimAuthClient(new CyaimAuthClientOptions
        {
            Authority = authority,
            ClientId = "wpf-client",            // Sample.AuthServer 已种子的公共客户端（无密钥）
            // Scopes 默认即 [permissions, offline_access]：权限声明 + 刷新令牌
        }, cache: cache);
    }

    /// <inheritdoc />
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 异步静默登录期间还没有任何窗口，先阻止应用因“最后窗口关闭”规则提前退出
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        InitializeClient(DefaultAuthority);

        bool restored = false;
        if (AuthClient.IsLoggedIn)
        {
            try
            {
                // 缓存中有令牌：验证仍有效（过期会自动用刷新令牌续期）
                await AuthClient.GetAccessTokenAsync();
                restored = true;
            }
            catch (InvalidOperationException)
            {
                // 令牌过期且无法刷新，走登录窗
            }
            catch (CyaimAuthException)
            {
                // 刷新被服务器拒绝，走登录窗
            }
            catch (HttpRequestException)
            {
                // 服务器不可达，走登录窗（可在登录窗修改地址后重试）
            }
        }

        Window window = restored ? new MainWindow() : new LoginWindow();
        MainWindow = window;
        ShutdownMode = ShutdownMode.OnLastWindowClose;
        window.Show();
    }
}
