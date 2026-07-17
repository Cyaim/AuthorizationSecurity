using System.Net.Http;
using System.Windows;
using System.Windows.Input;
using Cyaim.Authentication.Client;

namespace Sample.Wpf;

/// <summary>
/// 登录窗：资源所有者密码模式（grant_type=password）登录授权中心。
/// 全程 async/await，不阻塞 UI 线程；成功后打开 <see cref="MainWindow"/>。
/// </summary>
public partial class LoginWindow : Window
{
    /// <summary>创建登录窗</summary>
    public LoginWindow()
    {
        InitializeComponent();
        UserNameBox.Focus();
    }

    private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            LoginButton_Click(sender, e);
        }
    }

    private async void LoginButton_Click(object sender, RoutedEventArgs e)
    {
        string authority = ServerBox.Text.Trim();
        string userName = UserNameBox.Text.Trim();
        string password = PasswordBox.Password;

        if (authority.Length == 0 || userName.Length == 0 || password.Length == 0)
        {
            ErrorText.Text = "请填写服务器地址、用户名和密码。";
            return;
        }

        LoginButton.IsEnabled = false;
        ErrorText.Text = "正在登录……";
        try
        {
            // 服务器地址可编辑：与当前客户端不一致时重建单例
            App.InitializeClient(authority);

            await App.AuthClient.LoginWithPasswordAsync(userName, password);

            var main = new MainWindow();
            Application.Current.MainWindow = main;
            main.Show();
            Close();
        }
        catch (CyaimAuthException ex)
        {
            // 协议错误：invalid_grant（用户名/密码错误）、unauthorized_client 等
            ErrorText.Text = $"登录失败：{ex.Error} {ex.ErrorDescription}".TrimEnd();
        }
        catch (HttpRequestException ex)
        {
            ErrorText.Text = $"无法连接授权服务器 {authority}：{ex.Message}";
        }
        catch (UriFormatException)
        {
            ErrorText.Text = "服务器地址格式不正确，示例：http://127.0.0.1:5299";
        }
        finally
        {
            LoginButton.IsEnabled = true;
        }
    }
}
