using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Xunit;

namespace Cyaim.Authentication.IntegrationTests
{
    /// <summary>
    /// 安全修复端到端回归测试：
    /// 1. 口令重置后吊销刷新令牌 + 安全戳轮换使旧访问令牌失效；
    /// 2. 禁用账户后吊销刷新令牌 + 旧访问令牌失效；
    /// 3. 委派管理员（仅 auth.admin.users）无法授予角色/权限（职责分离守卫 403）；
    /// 4. 非法权限代码在用户/角色写接口被拒绝（400）；
    /// 5. 口令重置只失效旧会话，新口令重新登录后一切正常。
    /// </summary>
    public class SecurityFixIntegrationTests : IAsyncLifetime
    {
        private const string Api = "/auth-admin/api";

        private TestApp _app = null!;

        public async Task InitializeAsync() => _app = await TestApp.CreateAsync();

        public async Task DisposeAsync() => await _app.DisposeAsync();

        // ---------------------------------------------------------------- 帮助方法

        /// <summary>取管理员访问令牌（种子用户 admin 拥有 auth.admin.**）。</summary>
        private Task<string> AdminTokenAsync() =>
            _app.PasswordAccessTokenAsync("panel", "admin", "Admin!123");

        /// <summary>经管理 API 按用户名查用户Id。</summary>
        private async Task<string> FindUserIdAsync(string token, string userName)
        {
            using HttpResponseMessage response = await _app.AuthGetAsync($"{Api}/users?search={userName}", token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            foreach (JsonElement item in json.GetProperty("items").EnumerateArray())
            {
                if (item.GetProperty("userName").GetString() == userName)
                {
                    return item.GetProperty("id").GetString()!;
                }
            }
            throw new InvalidOperationException($"用户不存在：{userName}");
        }

        /// <summary>刷新令牌兑换（refresh_token 授权）。</summary>
        private Task<HttpResponseMessage> RefreshAsync(string clientId, string refreshToken)
        {
            return _app.PostFormAsync(AuthConstants.Endpoints.Token, new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = clientId,
                ["refresh_token"] = refreshToken,
            });
        }

        /// <summary>断言刷新令牌兑换失败：400 invalid_grant（已被吊销/失效）。</summary>
        private async Task AssertRefreshRejectedAsync(string refreshToken)
        {
            using HttpResponseMessage refresh = await RefreshAsync("panel", refreshToken);
            Assert.Equal(HttpStatusCode.BadRequest, refresh.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(refresh);
            Assert.Equal("invalid_grant", json.GetProperty("error").GetString());
        }

        // ---------------------------------------------------------------- 1. 口令重置吊销会话

        [Fact]
        public async Task ResetPassword_RevokesRefreshToken_And_OldAccessTokenForbidden()
        {
            // alice（order-admin：demo.order.**）登录，旧会话可正常访问资源
            JsonElement login = await _app.PasswordTokenAsync("panel", "alice", "alice123");
            string oldAccess = login.GetProperty("access_token").GetString()!;
            string oldRefresh = login.GetProperty("refresh_token").GetString()!;

            using (HttpResponseMessage before = await _app.AuthGetAsync("/t/read", oldAccess))
            {
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);
            }

            // 管理员重置 alice 口令
            string adminToken = await AdminTokenAsync();
            string aliceId = await FindUserIdAsync(adminToken, "alice");
            using (HttpResponseMessage reset = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users/{aliceId}/reset-password", adminToken,
                new { newPassword = "Alice!New1" }))
            {
                Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
            }

            // 旧刷新令牌已被吊销：兑换 400 invalid_grant（被盗用会话无法续命）
            await AssertRefreshRejectedAsync(oldRefresh);

            // 旧访问令牌携带过期安全戳：下次权限判断即失效 → 403
            using (HttpResponseMessage after = await _app.AuthGetAsync("/t/read", oldAccess))
            {
                Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 2. 口令重置只失效旧会话

        [Fact]
        public async Task ResetPassword_NewPasswordLoginWorks_OnlyOldSessionInvalidated()
        {
            // carol（order-admin-restricted：继承 demo.order.read）先登录，保留旧会话
            JsonElement oldLogin = await _app.PasswordTokenAsync("panel", "carol", "carol123");
            string oldAccess = oldLogin.GetProperty("access_token").GetString()!;

            string adminToken = await AdminTokenAsync();
            string carolId = await FindUserIdAsync(adminToken, "carol");
            using (HttpResponseMessage reset = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users/{carolId}/reset-password", adminToken,
                new { newPassword = "Carol!New1" }))
            {
                Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
            }

            // 旧口令登录被拒绝
            using (HttpResponseMessage stale = await _app.PasswordTokenResponseAsync("panel", "carol", "carol123"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, stale.StatusCode);
            }

            // 新口令登录成功，且新令牌（携带新安全戳）访问资源正常——只失效旧会话，不影响新登录
            string newAccess = await _app.PasswordAccessTokenAsync("panel", "carol", "Carol!New1");
            using (HttpResponseMessage fresh = await _app.AuthGetAsync("/t/read", newAccess))
            {
                Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
            }

            // 而重置前签发的旧访问令牌已失效
            using (HttpResponseMessage old = await _app.AuthGetAsync("/t/read", oldAccess))
            {
                Assert.Equal(HttpStatusCode.Forbidden, old.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 3. 禁用账户吊销会话

        [Fact]
        public async Task DisableUser_RevokesRefreshToken_And_OldAccessTokenForbidden()
        {
            // dave（order-viewer：demo.order.read）登录
            JsonElement login = await _app.PasswordTokenAsync("panel", "dave", "dave123");
            string oldAccess = login.GetProperty("access_token").GetString()!;
            string oldRefresh = login.GetProperty("refresh_token").GetString()!;

            using (HttpResponseMessage before = await _app.AuthGetAsync("/t/read", oldAccess))
            {
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);
            }

            // 管理员禁用 dave
            string adminToken = await AdminTokenAsync();
            string daveId = await FindUserIdAsync(adminToken, "dave");
            using (HttpResponseMessage disable = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{daveId}", adminToken,
                new { isEnabled = false }))
            {
                Assert.Equal(HttpStatusCode.OK, disable.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(disable);
                Assert.False(json.GetProperty("isEnabled").GetBoolean());
            }

            // 刷新令牌已吊销
            await AssertRefreshRejectedAsync(oldRefresh);

            // 旧访问令牌立即失效（禁用 + 安全戳轮换双保险）
            using (HttpResponseMessage after = await _app.AuthGetAsync("/t/read", oldAccess))
            {
                Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
            }

            // 禁用账户无法重新登录
            using (HttpResponseMessage relogin = await _app.PasswordTokenResponseAsync("panel", "dave", "dave123"))
            {
                Assert.Equal(HttpStatusCode.BadRequest, relogin.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 4. 委派管理员越权拦截

        [Fact]
        public async Task DelegatedAdmin_ManageUsersOnly_CannotGrantRolesOrPermissions()
        {
            // 管理员（具备 ManagePermissions）创建仅持 auth.admin.users 的委派管理员
            string adminToken = await AdminTokenAsync();
            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new
                {
                    userName = "limited-admin",
                    password = "Limited!123",
                    displayName = "受限管理员",
                    directPermissions = new[] { "auth.admin.users" },
                }))
            {
                Assert.Equal(HttpStatusCode.Created, create.StatusCode);
            }

            string limitedToken = await _app.PasswordAccessTokenAsync("panel", "limited-admin", "Limited!123");
            // 委派管理员具备 ManageUsers，可以查用户列表（正向路径）
            string bobId = await FindUserIdAsync(limitedToken, "bob");

            // 越权 1：给 bob 授予角色 → 需要 auth.admin.roles → 403
            using (HttpResponseMessage grantRole = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{bobId}", limitedToken,
                new { roles = new[] { "order-admin" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, grantRole.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(grantRole);
                Assert.Contains("auth.admin.roles", json.GetProperty("error").GetString());
            }

            // 越权 2：给 bob 授予直接权限 → 需要 auth.admin.permissions → 403
            using (HttpResponseMessage grantPerm = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{bobId}", limitedToken,
                new { directPermissions = new[] { "demo.order.delete" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, grantPerm.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(grantPerm);
                Assert.Contains("auth.admin.permissions", json.GetProperty("error").GetString());
            }

            // 越权 3：给 bob 设置拒绝权限（同属权限编辑）→ 403
            using (HttpResponseMessage denyPerm = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{bobId}", limitedToken,
                new { deniedPermissions = new[] { "demo.order.read" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, denyPerm.StatusCode);
            }

            // 越权 4：创建新用户时直接带角色 → 403（CreateUser 同一守卫）
            using (HttpResponseMessage createWithRole = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", limitedToken,
                new { userName = "mallory", password = "Mallory!123", roles = new[] { "admin" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, createWithRole.StatusCode);
            }

            // bob 的角色未被改动（403 不产生部分写入）
            using (HttpResponseMessage check = await _app.AuthGetAsync($"{Api}/users?search=bob", adminToken))
            {
                JsonElement json = await TestApp.ReadJsonAsync(check);
                foreach (JsonElement item in json.GetProperty("items").EnumerateArray())
                {
                    if (item.GetProperty("userName").GetString() == "bob")
                    {
                        Assert.Equal("order-viewer", Assert.Single(
                            item.GetProperty("roles").EnumerateArray()).GetString());
                    }
                }
            }

            // 职权范围内操作不受影响：仅改 displayName → 200
            using (HttpResponseMessage rename = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{bobId}", limitedToken,
                new { displayName = "Bob Renamed" }))
            {
                Assert.Equal(HttpStatusCode.OK, rename.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(rename);
                Assert.Equal("Bob Renamed", json.GetProperty("displayName").GetString());
            }

            // 创建不带角色/权限的普通用户 → 201（ManageUsers 的正当用途）
            using (HttpResponseMessage createPlain = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", limitedToken,
                new { userName = "plain-user", password = "Plain!123" }))
            {
                Assert.Equal(HttpStatusCode.Created, createPlain.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 5. 非法权限代码校验

        [Fact]
        public async Task InvalidPermissionCodes_Rejected400_ValidAccepted()
        {
            string adminToken = await AdminTokenAsync();

            // 创建用户：directPermissions 含 "sys.**.read"（** 只允许末段）→ 400
            using (HttpResponseMessage badDirect = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "badperm", password = "Bad!12345", directPermissions = new[] { "sys.**.read" } }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badDirect.StatusCode);
            }

            // 400 不产生部分写入：用户未被创建
            using (HttpResponseMessage search = await _app.AuthGetAsync($"{Api}/users?search=badperm", adminToken))
            {
                JsonElement json = await TestApp.ReadJsonAsync(search);
                Assert.Equal(0, json.GetProperty("total").GetInt32());
            }

            // 创建用户：deniedPermissions 含非法字符 → 400（防止非法拒绝规则被静默丢弃）
            using (HttpResponseMessage badDenied = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "badperm2", password = "Bad!12345", deniedPermissions = new[] { "bad!char" } }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badDenied.StatusCode);
            }

            // 更新用户：非法权限代码同样 400（UpdateUser 路径）
            string bobId = await FindUserIdAsync(adminToken, "bob");
            using (HttpResponseMessage badUpdate = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/users/{bobId}", adminToken,
                new { directPermissions = new[] { "sys.us*" } }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badUpdate.StatusCode);
            }

            // 创建角色：permissions 含 "sys.**.read" → 400（CreateRole 路径）
            using (HttpResponseMessage badRole = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/roles", adminToken,
                new { name = "bad-role", permissions = new[] { "sys.**.read" } }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badRole.StatusCode);
            }

            // 更新角色：deniedPermissions 非法 → 400（UpdateRole 路径）
            string roleId = await FindRoleIdAsync(adminToken, "order-viewer");
            using (HttpResponseMessage badRoleUpdate = await _app.AuthSendJsonAsync(
                HttpMethod.Put, $"{Api}/roles/{roleId}", adminToken,
                new { deniedPermissions = new[] { "bad!char" } }))
            {
                Assert.Equal(HttpStatusCode.BadRequest, badRoleUpdate.StatusCode);
            }

            // 合法权限代码正常放行：创建用户 201
            using (HttpResponseMessage goodUser = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "goodperm", password = "Good!12345", directPermissions = new[] { "demo.report.read" } }))
            {
                Assert.Equal(HttpStatusCode.Created, goodUser.StatusCode);
            }

            // 合法通配符（* 独占一段、** 位于末段）正常放行：创建角色 201
            using (HttpResponseMessage goodRole = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/roles", adminToken,
                new { name = "report-viewer", permissions = new[] { "demo.report.*", "demo.export.**" } }))
            {
                Assert.Equal(HttpStatusCode.Created, goodRole.StatusCode);
            }
        }

        // ---------------------------------------------------------------- 6. 仅认证端点也校验安全戳

        [Fact]
        public async Task ResetPassword_InvalidatesStaleToken_OnBareAuthEndpoint()
        {
            // /t/authed 仅要求已认证（RequirePermission() 无参），不判定具体权限，
            // 是安全戳校验最易被绕过的路径——验证口令重置后旧令牌在此端点同样被拒。
            string oldAccess = await _app.PasswordAccessTokenAsync("panel", "alice", "alice123");

            using (HttpResponseMessage before = await _app.AuthGetAsync("/t/authed", oldAccess))
            {
                Assert.Equal(HttpStatusCode.OK, before.StatusCode);
            }

            string adminToken = await AdminTokenAsync();
            string aliceId = await FindUserIdAsync(adminToken, "alice");
            using (HttpResponseMessage reset = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users/{aliceId}/reset-password", adminToken,
                new { newPassword = "Alice!New1" }))
            {
                Assert.Equal(HttpStatusCode.NoContent, reset.StatusCode);
            }

            // 安全戳失效：旧令牌在仅认证端点也被拒
            using (HttpResponseMessage after = await _app.AuthGetAsync("/t/authed", oldAccess))
            {
                Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
            }

            // 新令牌不受影响
            string newAccess = await _app.PasswordAccessTokenAsync("panel", "alice", "Alice!New1");
            using HttpResponseMessage fresh = await _app.AuthGetAsync("/t/authed", newAccess);
            Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        }

        // ---------------------------------------------------------------- 7. 越权：角色/客户端路径

        [Fact]
        public async Task DelegatedAdmin_ManageRolesOnly_CannotGrantPermissionsViaRole()
        {
            // 仅持 auth.admin.roles 的委派管理员
            string adminToken = await AdminTokenAsync();
            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "role-admin", password = "Role!12345", directPermissions = new[] { "auth.admin.roles" } }))
            {
                Assert.Equal(HttpStatusCode.Created, create.StatusCode);
            }
            string roleAdminToken = await _app.PasswordAccessTokenAsync("panel", "role-admin", "Role!12345");

            // 越权：建立含 auth.admin.** 权限的角色 → 需 ManagePermissions → 403（堵住经角色路径提权）
            using (HttpResponseMessage escalate = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/roles", roleAdminToken,
                new { name = "sneaky", permissions = new[] { "auth.admin.**" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, escalate.StatusCode);
            }

            // 职权内：建立不含权限的普通角色 → 201
            using (HttpResponseMessage ok = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/roles", roleAdminToken,
                new { name = "plain-role" }))
            {
                Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
            }
        }

        [Fact]
        public async Task DelegatedAdmin_ManageClientsOnly_CannotGrantPermissionsViaClient()
        {
            string adminToken = await AdminTokenAsync();
            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/users", adminToken,
                new { userName = "client-admin", password = "Client!1234", directPermissions = new[] { "auth.admin.clients" } }))
            {
                Assert.Equal(HttpStatusCode.Created, create.StatusCode);
            }
            string clientAdminToken = await _app.PasswordAccessTokenAsync("panel", "client-admin", "Client!1234");

            // 越权：建立 auth.admin.** 的 client_credentials 客户端 → 需 ManagePermissions → 403
            using (HttpResponseMessage escalate = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/clients", clientAdminToken,
                new { clientId = "evil-m2m", allowedGrantTypes = new[] { "client_credentials" }, permissions = new[] { "auth.admin.**" } }))
            {
                Assert.Equal(HttpStatusCode.Forbidden, escalate.StatusCode);
            }

            // 职权内：建立无权限客户端 → 201
            using (HttpResponseMessage ok = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/clients", clientAdminToken,
                new { clientId = "plain-client", allowedGrantTypes = new[] { "client_credentials" } }))
            {
                Assert.Equal(HttpStatusCode.Created, ok.StatusCode);
            }
        }

        [Fact]
        public async Task Roles_IsSystemFlag_NotMutableViaApi()
        {
            string adminToken = await AdminTokenAsync();

            // 建普通角色（IsSystem 应被忽略，即使请求带 isSystem:true）
            using (HttpResponseMessage create = await _app.AuthSendJsonAsync(
                HttpMethod.Post, $"{Api}/roles", adminToken,
                new { name = "not-system", isSystem = true }))
            {
                Assert.Equal(HttpStatusCode.Created, create.StatusCode);
                JsonElement json = await TestApp.ReadJsonAsync(create);
                Assert.False(json.GetProperty("isSystem").GetBoolean());
            }
        }

        [Fact]
        public async Task StaticAssets_UnknownPath_NotFound_WithoutCaching()
        {
            // 未知静态路径返回 404（且实现上不进缓存，避免游客用无限路径撑爆内存）
            using HttpResponseMessage r1 = await _app.Client.GetAsync("/auth-admin/does-not-exist-xyz");
            Assert.Equal(HttpStatusCode.NotFound, r1.StatusCode);
            using HttpResponseMessage r2 = await _app.Client.GetAsync("/auth-admin/another-random-9f8a7");
            Assert.Equal(HttpStatusCode.NotFound, r2.StatusCode);

            // 已知资源仍正常提供
            using HttpResponseMessage index = await _app.Client.GetAsync("/auth-admin");
            Assert.Equal(HttpStatusCode.OK, index.StatusCode);
        }

        /// <summary>经管理 API 按角色名查角色Id。</summary>
        private async Task<string> FindRoleIdAsync(string token, string roleName)
        {
            using HttpResponseMessage response = await _app.AuthGetAsync($"{Api}/roles", token);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            JsonElement json = await TestApp.ReadJsonAsync(response);
            foreach (JsonElement item in json.EnumerateArray())
            {
                if (item.GetProperty("name").GetString() == roleName)
                {
                    return item.GetProperty("id").GetString()!;
                }
            }
            throw new InvalidOperationException($"角色不存在：{roleName}");
        }
    }
}
