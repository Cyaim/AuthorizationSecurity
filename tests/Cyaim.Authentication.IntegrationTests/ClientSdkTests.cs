using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Client;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// Client SDK 端到端：密码登录、UserInfo/权限加载、本地权限判断、过期自动刷新、消息处理器自动附令牌。
    /// </summary>
    public class ClientSdkTests : IAsyncLifetime
    {
        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        private CyaimAuthClient CreateSdkClient(Action<CyaimAuthClientOptions>? configure = null)
        {
            var options = new CyaimAuthClientOptions
            {
                Authority = "http://localhost",
                ClientId = "panel",
            };
            configure?.Invoke(options);
            return new CyaimAuthClient(options, httpClient: _app.Client);
        }

        [Fact]
        public async Task PasswordLogin_UserInfo_And_PermissionChecks_Alice()
        {
            using CyaimAuthClient sdk = CreateSdkClient();

            await sdk.LoginWithPasswordAsync("alice", "alice123");
            Assert.True(sdk.IsLoggedIn);
            Assert.NotNull(sdk.CurrentToken);

            UserInfoResponse userInfo = await sdk.GetUserInfoAsync();
            Assert.Equal("alice", userInfo.PreferredUsername);
            Assert.NotNull(userInfo.Role);
            Assert.Contains("order-admin", userInfo.Role!);

            await sdk.LoadPermissionsAsync();
            Assert.NotNull(sdk.GrantedPermissions);
            Assert.True(sdk.HasPermission("demo.order.read"));
            Assert.True(sdk.HasPermission("demo.order.delete"));   // alice 持有 demo.order.**
        }

        [Fact]
        public async Task PermissionChecks_Bob_ReadOnly()
        {
            using CyaimAuthClient sdk = CreateSdkClient();

            await sdk.LoginWithPasswordAsync("bob", "bob123");
            await sdk.LoadPermissionsAsync();

            Assert.True(sdk.HasPermission("demo.order.read"));
            Assert.False(sdk.HasPermission("demo.order.delete"));
        }

        [Fact]
        public async Task GetAccessToken_ExpiredToken_AutoRefreshes()
        {
            // 客户端访问令牌有效期设为 1 秒：默认 60 秒 RefreshSkew 下登录后立即视为过期
            IClientStore clients = _app.Services.GetRequiredService<IClientStore>();
            ClientApplication panel = (await clients.FindByClientIdAsync("panel"))!;
            panel.AccessTokenLifetimeSeconds = 1;
            await clients.UpdateAsync(panel);

            using CyaimAuthClient sdk = CreateSdkClient();
            await sdk.LoginWithPasswordAsync("alice", "alice123");
            string firstAccessToken = sdk.CurrentToken!.AccessToken;
            string? firstRefreshToken = sdk.CurrentToken.RefreshToken;
            Assert.False(string.IsNullOrEmpty(firstRefreshToken));

            bool tokenChanged = false;
            sdk.TokenChanged += (_, _) => tokenChanged = true;

            string refreshed = await sdk.GetAccessTokenAsync();

            Assert.True(tokenChanged, "过期令牌应触发自动刷新（TokenChanged）");
            Assert.NotEqual(firstAccessToken, refreshed);
            Assert.NotEqual(firstRefreshToken, sdk.CurrentToken!.RefreshToken);   // 刷新令牌已轮换
        }

        [Fact]
        public async Task MessageHandler_AttachesBearer_ResourceCallSucceeds()
        {
            using CyaimAuthClient sdk = CreateSdkClient();
            await sdk.LoginWithPasswordAsync("bob", "bob123");

            using var http = new HttpClient(
                new CyaimAuthHttpMessageHandler(sdk, _app.Server.CreateHandler()))
            {
                BaseAddress = new Uri("http://localhost"),
            };

            using HttpResponseMessage response = await http.GetAsync("/t/read", CancellationToken.None);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("read-ok", await response.Content.ReadAsStringAsync());
        }
    }
}
