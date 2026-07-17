using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Client;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// OAuth2/OIDC 流程：client_credentials、authorization_code + PKCE + SSO、
    /// refresh_token 轮换与重放防护、自省与吊销、登出。
    /// </summary>
    public class OAuthFlowTests : IAsyncLifetime
    {
        private const string RedirectUri = "http://localhost/callback";

        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        // ---------------------------------------------------------------- client_credentials

        [Fact]
        public async Task ClientCredentials_Success_TokenAccessesPermittedResource()
        {
            using HttpResponseMessage response = await _app.PostFormAsync(
                AuthConstants.Endpoints.Token,
                new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["scope"] = "permissions",
                },
                basic: ("m2m", "m2m-secret"));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            string token = json.GetProperty("access_token").GetString()!;

            using HttpResponseMessage resource = await _app.AuthGetAsync("/t/read", token);
            Assert.Equal(HttpStatusCode.OK, resource.StatusCode);
        }

        [Fact]
        public async Task ClientCredentials_WrongSecret_Returns401_InvalidClient()
        {
            using HttpResponseMessage response = await _app.PostFormAsync(
                AuthConstants.Endpoints.Token,
                new Dictionary<string, string> { ["grant_type"] = "client_credentials" },
                basic: ("m2m", "wrong-secret"));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            Assert.Equal("invalid_client", json.GetProperty("error").GetString());
        }

        // ---------------------------------------------------------------- authorization_code + PKCE

        [Fact]
        public async Task AuthorizationCodePkce_FullFlow_Sso_WrongVerifier_And_CodeReplay()
        {
            string verifier = Pkce.CreateCodeVerifier();
            string challenge = Pkce.CreateCodeChallenge(verifier);
            string authorizeUrl = BuildAuthorizeUrl(challenge, state: "st-123");

            // 1. 未登录：302 跳转登录页
            using (HttpResponseMessage anonymous = await _app.Client.GetAsync(authorizeUrl))
            {
                Assert.Equal(HttpStatusCode.Found, anonymous.StatusCode);
                string location = anonymous.Headers.Location!.ToString();
                Assert.StartsWith(AuthConstants.Endpoints.Login, location);
                Assert.Contains("returnUrl=", location);
            }

            // 2. 提交登录表单：302 且 Set-Cookie cyaim_sso
            string cookie = await LoginForSsoCookieAsync("alice", "alice123", authorizeUrl);

            // 3. 携带 SSO Cookie 再次授权：302 回调携带 code + state
            string code = await AuthorizeForCodeAsync(authorizeUrl, cookie, expectedState: "st-123");

            // 4. 正确 verifier 兑换成功
            using (HttpResponseMessage exchange = await ExchangeCodeAsync(code, verifier))
            {
                Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(exchange);
                Assert.False(string.IsNullOrEmpty(json.GetProperty("access_token").GetString()));
                Assert.False(string.IsNullOrEmpty(json.GetProperty("refresh_token").GetString()));
            }

            // 5. code 重放：400
            using (HttpResponseMessage replay = await ExchangeCodeAsync(code, verifier))
            {
                Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(replay);
                Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
            }

            // 6. SSO：同 Cookie 免登录直接拿新 code；错误 verifier 兑换 400
            string secondCode = await AuthorizeForCodeAsync(authorizeUrl, cookie, expectedState: "st-123");
            Assert.NotEqual(code, secondCode);
            using (HttpResponseMessage badVerifier = await ExchangeCodeAsync(secondCode, Pkce.CreateCodeVerifier()))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badVerifier.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(badVerifier);
                Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
            }
        }

        [Fact]
        public async Task Logout_ClearsSsoCookie_AuthorizeRequiresLoginAgain()
        {
            string verifier = Pkce.CreateCodeVerifier();
            string authorizeUrl = BuildAuthorizeUrl(Pkce.CreateCodeChallenge(verifier), state: null);

            string cookie = await LoginForSsoCookieAsync("bob", "bob123", authorizeUrl);
            await AuthorizeForCodeAsync(authorizeUrl, cookie, expectedState: null);

            // 登出：响应必须下发 cyaim_sso 删除 Cookie
            using (var logoutRequest = new HttpRequestMessage(HttpMethod.Get, AuthConstants.Endpoints.Logout))
            {
                logoutRequest.Headers.Add("Cookie", cookie);
                using HttpResponseMessage logout = await _app.Client.SendAsync(logoutRequest);
                Assert.Equal(HttpStatusCode.OK, logout.StatusCode);
                string setCookie = string.Join(";", logout.Headers.GetValues("Set-Cookie"));
                Assert.Contains("cyaim_sso=", setCookie);
                Assert.Contains("expires=", setCookie, StringComparison.OrdinalIgnoreCase);
            }

            // 浏览器丢弃 Cookie 后再授权：又要求登录
            using HttpResponseMessage authorize = await _app.Client.GetAsync(authorizeUrl);
            Assert.Equal(HttpStatusCode.Found, authorize.StatusCode);
            Assert.StartsWith(AuthConstants.Endpoints.Login, authorize.Headers.Location!.ToString());
        }

        // ---------------------------------------------------------------- refresh_token

        [Fact]
        public async Task RefreshToken_Rotates_And_ReplayRevokesFamily()
        {
            JsonElement login = await _app.PasswordTokenAsync("panel", "alice", "alice123");
            string rt1 = login.GetProperty("refresh_token").GetString()!;

            // 轮换：新旧刷新令牌不同
            string rt2;
            using (HttpResponseMessage refresh = await RefreshAsync("panel", rt1))
            {
                Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(refresh);
                rt2 = json.GetProperty("refresh_token").GetString()!;
                Assert.NotEqual(rt1, rt2);
            }

            // 重放旧令牌：400 且整个家族吊销
            using (HttpResponseMessage replay = await RefreshAsync("panel", rt1))
            {
                Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(replay);
                Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
            }

            // 新令牌同家族，同样被吊销
            using (HttpResponseMessage revoked = await RefreshAsync("panel", rt2))
            {
                Assert.Equal(HttpStatusCode.BadRequest, revoked.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(revoked);
                Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
            }
        }

        // ---------------------------------------------------------------- 自省与吊销

        [Fact]
        public async Task Introspection_ActiveAccessToken_And_RevokedRefreshToken()
        {
            JsonElement login = await _app.PasswordTokenAsync("panel", "alice", "alice123");
            string accessToken = login.GetProperty("access_token").GetString()!;
            string refreshToken = login.GetProperty("refresh_token").GetString()!;

            // 访问令牌自省（Basic 客户端认证）：active:true
            using (HttpResponseMessage introspect = await _app.PostFormAsync(
                AuthConstants.Endpoints.Introspect,
                new Dictionary<string, string> { ["token"] = accessToken },
                basic: ("m2m", "m2m-secret")))
            {
                Assert.Equal(HttpStatusCode.OK, introspect.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(introspect);
                Assert.True(json.GetProperty("active").GetBoolean());
                Assert.Equal("alice", json.GetProperty("username").GetString());
            }

            // 吊销刷新令牌（持有令牌的 panel 客户端）
            using (HttpResponseMessage revoke = await _app.PostFormAsync(
                AuthConstants.Endpoints.Revoke,
                new Dictionary<string, string>
                {
                    ["client_id"] = "panel",
                    ["token"] = refreshToken,
                    ["token_type_hint"] = "refresh_token",
                }))
            {
                Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
            }

            // 已吊销刷新令牌自省：active:false
            using (HttpResponseMessage introspect = await _app.PostFormAsync(
                AuthConstants.Endpoints.Introspect,
                new Dictionary<string, string> { ["token"] = refreshToken },
                basic: ("m2m", "m2m-secret")))
            {
                Assert.Equal(HttpStatusCode.OK, introspect.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(introspect);
                Assert.False(json.GetProperty("active").GetBoolean());
            }

            // 吊销后刷新不可用
            using (HttpResponseMessage refresh = await RefreshAsync("panel", refreshToken))
            {
                Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 帮助方法

        private string BuildAuthorizeUrl(string codeChallenge, string? state)
        {
            var query = new Dictionary<string, string?>
            {
                ["response_type"] = "code",
                ["client_id"] = "web",
                ["redirect_uri"] = RedirectUri,
                ["scope"] = "openid profile permissions offline_access",
                ["code_challenge"] = codeChallenge,
                ["code_challenge_method"] = "S256",
            };
            if (state != null)
            {
                query["state"] = state;
            }
            return QueryHelpers.AddQueryString(AuthConstants.Endpoints.Authorize, query);
        }

        /// <summary>
        /// 提交登录表单并提取 cyaim_sso Cookie（TestServer 无 CookieContainer，手动携带）。
        /// </summary>
        private async Task<string> LoginForSsoCookieAsync(string user, string pass, string returnUrl)
        {
            using HttpResponseMessage response = await _app.PostFormAsync(
                AuthConstants.Endpoints.Login,
                new Dictionary<string, string>
                {
                    ["username"] = user,
                    ["password"] = pass,
                    ["returnUrl"] = returnUrl,
                });

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            string? cookie = response.Headers.GetValues("Set-Cookie")
                .Where(v => v.StartsWith("cyaim_sso=", StringComparison.Ordinal))
                .Select(v => v.Split(';')[0])
                .FirstOrDefault();
            Assert.False(string.IsNullOrEmpty(cookie), "登录成功必须下发 cyaim_sso Cookie");
            return cookie!;
        }

        /// <summary>
        /// 携带 SSO Cookie 请求授权端点并从回调地址提取授权码。
        /// </summary>
        private async Task<string> AuthorizeForCodeAsync(string authorizeUrl, string cookie, string? expectedState)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, authorizeUrl);
            request.Headers.Add("Cookie", cookie);
            using HttpResponseMessage response = await _app.Client.SendAsync(request);

            Assert.Equal(HttpStatusCode.Found, response.StatusCode);
            Uri location = response.Headers.Location!;
            Assert.StartsWith(RedirectUri, location.ToString());

            Dictionary<string, Microsoft.Extensions.Primitives.StringValues> query =
                QueryHelpers.ParseQuery(location.Query);
            Assert.True(query.ContainsKey("code"), $"回调应携带 code，实际：{location}");
            if (expectedState != null)
            {
                Assert.Equal(expectedState, query["state"].ToString());
            }
            return query["code"].ToString();
        }

        private Task<HttpResponseMessage> ExchangeCodeAsync(string code, string verifier)
        {
            return _app.PostFormAsync(AuthConstants.Endpoints.Token, new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "web",
                ["code"] = code,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = verifier,
            });
        }

        private Task<HttpResponseMessage> RefreshAsync(string clientId, string refreshToken)
        {
            return _app.PostFormAsync(AuthConstants.Endpoints.Token, new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = clientId,
                ["refresh_token"] = refreshToken,
            });
        }
    }
}
