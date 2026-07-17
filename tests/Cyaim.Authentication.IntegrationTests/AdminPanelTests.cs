using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// 管理面板 REST API：匿名配置、当前主体、用户 CRUD 全链、权限隔离、审计查询、客户端密钥轮换。
    /// </summary>
    public class AdminPanelTests : IAsyncLifetime
    {
        private const string Api = "/auth-admin/api";

        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        [Fact]
        public async Task Config_Anonymous_Returns200()
        {
            using HttpResponseMessage response = await _app.Client.GetAsync($"{Api}/config");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.False(string.IsNullOrEmpty(json.GetProperty("tokenEndpoint").GetString()));
        }

        [Fact]
        public async Task Me_AdminToken_AllAdminPermissionsTrue()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");

            using HttpResponseMessage response = await _app.AuthGetAsync($"{Api}/me", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement permissions = (await TestApp.ReadJsonAsync(response)).GetProperty("permissions");
            Assert.True(permissions.GetProperty("read").GetBoolean());
            Assert.True(permissions.GetProperty("manageUsers").GetBoolean());
            Assert.True(permissions.GetProperty("manageRoles").GetBoolean());
            Assert.True(permissions.GetProperty("managePermissions").GetBoolean());
            Assert.True(permissions.GetProperty("manageClients").GetBoolean());
            Assert.True(permissions.GetProperty("readAudit").GetBoolean());
        }

        [Fact]
        public async Task Users_CrudFullChain_Create_Read_UpdateRoles_ResetPassword_Delete()
        {
            string adminToken = await _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");

            // 创建
            string userId;
            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "eve", password = "Eve!12345", roles = new[] { "order-viewer" }, displayName = "Eve" }))
            {
                Assert.Equal(HttpStatusCode.Created, create.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(create);
                userId = json.GetProperty("id").GetString()!;
                Assert.Equal("eve", json.GetProperty("userName").GetString());
            }

            // 读取
            using (HttpResponseMessage list = await _app.AuthGetAsync($"{Api}/users?search=eve", adminToken))
            {
                Assert.Equal(HttpStatusCode.OK, list.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(list);
                Assert.Contains(json.GetProperty("items").EnumerateArray(),
                    u => u.GetProperty("id").GetString() == userId);
            }

            // 更新角色
            using (HttpResponseMessage update = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{userId}", adminToken,
                new { roles = new[] { "order-admin" } }))
            {
                Assert.Equal(HttpStatusCode.OK, update.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(update);
                List<string> roles = json.GetProperty("roles").EnumerateArray()
                    .Select(e => e.GetString()!).ToList();
                Assert.Equal(new[] { "order-admin" }, roles);
            }

            // 重置密码
            using (HttpResponseMessage reset = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users/{userId}/reset-password", adminToken,
                new { newPassword = "Eve!NewPass1" }))
            {
                Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
            }

            // 旧密码登录 400，新密码 200
            using (HttpResponseMessage oldLogin = await _app.PasswordTokenResponseAsync("panel", "eve", "Eve!12345"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, oldLogin.StatusCode);
            }
            using (HttpResponseMessage newLogin = await _app.PasswordTokenResponseAsync("panel", "eve", "Eve!NewPass1"))
            {
                Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
            }

            // 删除
            using (HttpResponseMessage delete = await _app.AuthSendAsync(
                HttpMethod.Delete, $"{Api}/users/{userId}", adminToken))
            {
                Assert.Equal(HttpStatusCode.NoContent, delete.StatusCode);
            }
            using (HttpResponseMessage loginAfterDelete = await _app.PasswordTokenResponseAsync("panel", "eve", "Eve!NewPass1"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, loginAfterDelete.StatusCode);
            }
        }

        [Fact]
        public async Task Bob_WithoutAdminPermissions_Gets403_OnReadAndWrite()
        {
            string bobToken = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using (HttpResponseMessage list = await _app.AuthGetAsync($"{Api}/users", bobToken))
            {
                Assert.Equal(HttpStatusCode.Forbidden, list.StatusCode);
            }

            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", bobToken,
                new { userName = "mallory", password = "Mallory!123" }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, create.StatusCode);
            }
        }

        [Fact]
        public async Task Audit_QueryByDeniedOutcome_FindsPriorDenial()
        {
            // 先制造一次拒绝
            string bobToken = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");
            using (HttpResponseMessage denied = await _app.AuthSendAsync(HttpMethod.Delete, "/t/del", bobToken))
            {
                Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
            }

            string adminToken = await _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");
            using HttpResponseMessage response = await _app.AuthGetAsync($"{Api}/audit?outcome=Denied", adminToken);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Contains(json.GetProperty("items").EnumerateArray(), item =>
                item.GetProperty("outcome").GetString() == "Denied" &&
                item.GetProperty("resource").GetString() == "/t/del");
        }

        [Fact]
        public async Task RegenerateClientSecret_ReturnsPlaintext_NewSecretWorks_OldSecretRejected()
        {
            string adminToken = await _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");

            string newSecret;
            using (HttpResponseMessage regenerate = await _app.AuthSendAsync(
                HttpMethod.Post, $"{Api}/clients/m2m/regenerate-secret", adminToken,
                new StringContent("{}", Encoding.UTF8, "application/json")))
            {
                Assert.Equal(HttpStatusCode.OK, regenerate.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(regenerate);
                newSecret = json.GetProperty("secret").GetString()!;
                Assert.False(string.IsNullOrEmpty(newSecret));
            }

            // 新密钥可 client_credentials 登录
            using (HttpResponseMessage newLogin = await _app.PostFormAsync(
                AuthConstants.Endpoints.Token,
                new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
                basic: ("m2m", newSecret)))
            {
                Assert.Equal(HttpStatusCode.OK, newLogin.StatusCode);
            }

            // 旧密钥被拒绝
            using (HttpResponseMessage oldLogin = await _app.PostFormAsync(
                AuthConstants.Endpoints.Token,
                new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
                basic: ("m2m", "m2m-secret")))
            {
                Assert.Equal(HttpStatusCode.Unauthorized, oldLogin.StatusCode);
            }
        }
    }
}
