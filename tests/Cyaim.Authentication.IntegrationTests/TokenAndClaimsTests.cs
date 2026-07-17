using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// 令牌与声明：密码授权响应形态、UserInfo 声明还原、禁用用户即时生效。
    /// </summary>
    public class TokenAndClaimsTests : IAsyncLifetime
    {
        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        [Fact]
        public async Task PasswordGrant_ResponseShape_And_CacheControlNoStore()
        {
            using HttpResponseMessage response = await _app.PasswordTokenResponseAsync("panel", "alice", "alice123");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.NotNull(response.Headers.CacheControl);
            Assert.True(response.Headers.CacheControl!.NoStore, "令牌响应必须带 Cache-Control: no-store");

            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.False(string.IsNullOrEmpty(json.GetProperty("access_token").GetString()));
            Assert.False(string.IsNullOrEmpty(json.GetProperty("refresh_token").GetString()));
            Assert.True(json.GetProperty("expires_in").GetInt32() > 0);
            Assert.Equal("Bearer", json.GetProperty("token_type").GetString());
            string scope = json.GetProperty("scope").GetString()!;
            Assert.Contains("permissions", scope);
            Assert.Contains("offline_access", scope);
        }

        [Fact]
        public async Task UserInfo_RestoresRolesAndPermissionsFromToken()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "alice", "alice123");

            using HttpResponseMessage response = await _app.AuthGetAsync(AuthConstants.Endpoints.UserInfo, token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Equal("alice", json.GetProperty("preferred_username").GetString());

            List<string> roles = json.GetProperty("role").EnumerateArray()
                .Select(e => e.GetString()!).ToList();
            Assert.Contains("order-admin", roles);

            List<string> permissions = json.GetProperty("permissions").EnumerateArray()
                .Select(e => e.GetString()!).ToList();
            Assert.Contains("demo.order.**", permissions);
            Assert.Contains("demo.ws.**", permissions);
        }

        [Fact]
        public async Task DisabledUser_LoginRejected_And_IssuedTokenDeniedOnNextCheck()
        {
            // 禁用前：登录成功且令牌可用
            string daveToken = await _app.PasswordAccessTokenAsync("panel", "dave", "dave123");
            using (HttpResponseMessage before = await _app.AuthGetAsync("/t/read", daveToken))
            {
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);
            }

            // 管理 API 禁用 dave
            string adminToken = await _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");
            string daveId = await FindUserIdAsync(adminToken, "dave");
            using (HttpResponseMessage update = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"/auth-admin/api/users/{daveId}", adminToken, new { isEnabled = false }))
            {
                Assert.Equal(HttpStatusCode.OK, update.StatusCode);
            }

            // 再登录：400 invalid_grant
            using (HttpResponseMessage login = await _app.PasswordTokenResponseAsync("panel", "dave", "dave123"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, login.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(login);
                Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
            }

            // 已发令牌在下次权限判断时被拒（评估器禁用检测）
            using (HttpResponseMessage after = await _app.AuthGetAsync("/t/read", daveToken))
            {
                Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(after);
                Assert.Equal("SubjectDisabled", json.GetProperty("error_description").GetString());
            }
        }

        private async Task<string> FindUserIdAsync(string adminToken, string userName)
        {
            using HttpResponseMessage response = await _app.AuthGetAsync(
                $"/auth-admin/api/users?search={userName}", adminToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            JsonElement user = json.GetProperty("items").EnumerateArray()
                .Single(u => u.GetProperty("userName").GetString() == userName);
            return user.GetProperty("id").GetString()!;
        }
    }
}
