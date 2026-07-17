using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// 权限中间件矩阵：401/403 语义、拒绝优先、层级继承、RequireAll、AllowGuest、无参 RequirePermission 与 ABAC 策略。
    /// </summary>
    public class MiddlewareMatrixTests : IAsyncLifetime
    {
        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        [Fact]
        public async Task NoToken_ProtectedEndpoint_Returns401_WithWwwAuthenticateBearer()
        {
            using HttpResponseMessage response = await _app.Client.GetAsync("/t/read");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.True(response.Headers.Contains("WWW-Authenticate"));
            string header = string.Join(",", response.Headers.GetValues("WWW-Authenticate"));
            Assert.StartsWith("Bearer", header);
        }

        [Fact]
        public async Task ForgedToken_Returns401_InvalidToken()
        {
            using HttpResponseMessage response = await _app.AuthGetAsync(
                "/t/read", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.forged-signature");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            string header = string.Join(",", response.Headers.GetValues("WWW-Authenticate"));
            Assert.Contains("invalid_token", header);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Equal("invalid_token", json.GetProperty("error").GetString());
        }

        [Fact]
        public async Task Bob_Read_Returns200()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/read", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task Bob_Delete_Returns403_NoMatchingGrant()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthSendAsync(HttpMethod.Delete, "/t/del", token);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Equal("forbidden", json.GetProperty("error").GetString());
            Assert.Equal("NoMatchingGrant", json.GetProperty("error_description").GetString());
        }

        [Fact]
        public async Task Carol_Delete_Returns403_DeniedByRule_DenyWins()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "carol", "carol123");

            using HttpResponseMessage response = await _app.AuthSendAsync(HttpMethod.Delete, "/t/del", token);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Contains("DeniedByRule", json.GetProperty("error_description").GetString());
        }

        [Fact]
        public async Task Carol_Read_Returns200_ViaRoleHierarchy()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "carol", "carol123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/read", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task RequireAll_Alice_HasReadAndCreate_Returns200()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "alice", "alice123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/all", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task RequireAll_Bob_MissingCreate_Returns403()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/all", token);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task AllowGuest_Anonymous_Returns200()
        {
            using HttpResponseMessage response = await _app.Client.GetAsync("/t/open");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("open-ok", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task AuthedOnly_NoToken_Returns401()
        {
            using HttpResponseMessage response = await _app.Client.GetAsync("/t/authed");

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthedOnly_WithToken_Returns200()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/authed", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task Policy_Even_True_Returns200()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/policy", token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task Policy_Odd_False_Returns403()
        {
            string token = await _app.PasswordAccessTokenAsync("panel", "bob", "bob123");

            using HttpResponseMessage response = await _app.AuthGetAsync("/t/policy-odd", token);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Equal("PolicyNotSatisfied", json.GetProperty("error_description").GetString());
        }
    }
}
