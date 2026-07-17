using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using Cyaim.Authentication.Client;

namespace Sample.Wpf;

/// <summary>
/// 主窗口：展示当前用户与角色、按本地权限集（HasPermission）启停操作按钮、
/// 用 <see cref="CyaimAuthHttpMessageHandler"/> 调用资源 API（自动附带 Bearer、401 自动刷新重试）。
/// SDK 事件可能在任意线程触发，统一用 Dispatcher.Invoke 回 UI 线程。
/// </summary>
public partial class MainWindow : Window
{
    private readonly CyaimAuthClient _client;
    private readonly HttpClient _api;
    private bool _leavingToLogin;

    /// <summary>创建主窗口（要求 App.AuthClient 已登录或已从缓存恢复）</summary>
    public MainWindow()
    {
        InitializeComponent();

        _client = App.AuthClient;

        // 调用资源 API 的 HttpClient：委托处理器自动附加访问令牌，401 时刷新一次并重试
        _api = new HttpClient(new CyaimAuthHttpMessageHandler(_client, new HttpClientHandler()));

        _client.TokenChanged += OnTokenChanged;
        _client.SessionExpired += OnSessionExpired;
        Closed += (_, _) => Cleanup();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Log("正在加载用户信息与权限……");
        try
        {
            // UserInfo 端点：显示名 / 用户名 / 角色
            UserInfoResponse info = await _client.GetUserInfoAsync();
            UserText.Text = $"当前用户：{info.Name ?? info.PreferredUsername ?? info.Sub}" +
                            (info.PreferredUsername != null ? $"（{info.PreferredUsername}）" : string.Empty);
            RoleText.Text = "角色：" + (info.Role is { Length: > 0 } ? string.Join("、", info.Role) : "（无）");

            // 从 UserInfo 加载权限并编译为本地权限集，之后 HasPermission 离线判定
            await _client.LoadPermissionsAsync();
            Log($"权限加载完成：{string.Join(", ", _client.GrantedPermissions ?? Array.Empty<string>())}");
        }
        catch (CyaimAuthException ex)
        {
            UserText.Text = "用户信息加载失败";
            Log($"加载用户信息失败：{ex.Error} {ex.ErrorDescription}");

            // 联网失败时退化：从访问令牌的 perm 声明离线解析权限
            if (_client.LoadPermissionsFromToken())
            {
                Log("已改为从访问令牌离线解析权限。");
            }
        }
        catch (HttpRequestException ex)
        {
            UserText.Text = "用户信息加载失败（服务器不可达）";
            Log($"网络错误：{ex.Message}");
            if (_client.LoadPermissionsFromToken())
            {
                Log("已改为从访问令牌离线解析权限。");
            }
        }
        catch (InvalidOperationException ex)
        {
            // 令牌过期且无法刷新
            Log($"会话不可用：{ex.Message}");
            BackToLogin();
            return;
        }

        UpdatePermissionButtons();
    }

    /// <summary>按权限启停操作按钮，并把原因写进 ToolTip</summary>
    private void UpdatePermissionButtons()
    {
        ApplyGate(ReadOrderButton, "demo.order.read");
        ApplyGate(CreateOrderButton, "demo.order.create");
        ApplyGate(DeleteOrderButton, "demo.order.delete");

        static void ApplyGate(Button button, string permission)
        {
            bool granted = App.AuthClient.HasPermission(permission);
            button.IsEnabled = granted;
            button.ToolTip = granted
                ? $"已授予权限 {permission}"
                : $"缺少权限 {permission}，按钮已禁用";
            // 禁用状态也显示 ToolTip，让用户看到禁用原因
            ToolTipService.SetShowOnDisabled(button, true);
        }
    }

    private void ReadOrderButton_Click(object sender, RoutedEventArgs e) =>
        Log("执行「查看订单」：本地权限 demo.order.read 通过。");

    private void CreateOrderButton_Click(object sender, RoutedEventArgs e) =>
        Log("执行「创建订单」：本地权限 demo.order.create 通过。");

    private void DeleteOrderButton_Click(object sender, RoutedEventArgs e) =>
        Log("执行「删除订单」：本地权限 demo.order.delete 通过。");

    private async void CallApiButton_Click(object sender, RoutedEventArgs e)
    {
        string apiBase = ApiBaseBox.Text.Trim().TrimEnd('/');
        if (apiBase.Length == 0)
        {
            ApiResultBox.Text = "请填写资源 API 地址。";
            return;
        }

        CallApiButton.IsEnabled = false;
        try
        {
            string url = apiBase + "/api/orders";
            Log($"GET {url}");
            using HttpResponseMessage response = await _api.GetAsync(url);
            string body = await response.Content.ReadAsStringAsync();
            ApiResultBox.Text = $"HTTP {(int)response.StatusCode} {response.StatusCode}\n{body}";
            Log($"响应 HTTP {(int)response.StatusCode}");
        }
        catch (HttpRequestException ex)
        {
            ApiResultBox.Text = $"请求失败：{ex.Message}";
            Log($"请求失败：{ex.Message}");
        }
        catch (UriFormatException)
        {
            ApiResultBox.Text = "API 地址格式不正确，示例：http://127.0.0.1:5298";
        }
        catch (InvalidOperationException ex)
        {
            // 令牌过期且无法刷新（SessionExpired 事件会引导回登录窗）
            ApiResultBox.Text = $"会话不可用：{ex.Message}";
        }
        finally
        {
            CallApiButton.IsEnabled = true;
        }
    }

    private async void LogoutButton_Click(object sender, RoutedEventArgs e)
    {
        LogoutButton.IsEnabled = false;
        try
        {
            // 向服务器吊销刷新令牌（尽力而为）并清空本地令牌与缓存文件
            await _client.LogoutAsync();
        }
        finally
        {
            BackToLogin();
        }
    }

    // ---------- SDK 事件（可能来自任意线程，必须回 UI 线程） ----------

    private void OnTokenChanged(object? sender, EventArgs e)
    {
        Dispatcher.Invoke(() =>
            Log(_client.IsLoggedIn ? "令牌已更新（登录或自动刷新）。" : "令牌已清除。"));
    }

    private void OnSessionExpired(object? sender, EventArgs e)
    {
        Dispatcher.Invoke(() =>
        {
            if (_leavingToLogin)
            {
                return;
            }

            Log("会话已过期：刷新令牌被服务器拒绝。");
            MessageBox.Show(this, "登录会话已过期，请重新登录。", "会话过期",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            BackToLogin();
        });
    }

    // ---------- 辅助 ----------

    /// <summary>回到登录窗并关闭主窗</summary>
    private void BackToLogin()
    {
        if (_leavingToLogin)
        {
            return;
        }
        _leavingToLogin = true;

        var login = new LoginWindow();
        Application.Current.MainWindow = login;
        login.Show();
        Close();
    }

    private void Cleanup()
    {
        _client.TokenChanged -= OnTokenChanged;
        _client.SessionExpired -= OnSessionExpired;
        _api.Dispose();
    }

    private void Log(string message)
    {
        LogList.Items.Add($"[{DateTime.Now:HH:mm:ss}] {message}");
        LogList.ScrollIntoView(LogList.Items[^1]);
    }
}
