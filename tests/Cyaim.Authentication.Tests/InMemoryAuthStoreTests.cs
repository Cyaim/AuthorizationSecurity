using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Stores;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="InMemoryAuthStore"/> 测试：CRUD、唯一性、深拷贝隔离、版本号、令牌存储。
    /// </summary>
    public class InMemoryAuthStoreTests
    {
        private readonly InMemoryAuthStore _store = new InMemoryAuthStore();

        #region 用户

        [Fact]
        public async Task 用户CRUD()
        {
            var user = new AuthUser { Id = "u1", UserName = "Alice", Email = "alice@example.com" };
            await _store.CreateAsync(user);

            AuthUser? byId = await _store.FindByIdAsync("u1");
            Assert.NotNull(byId);
            Assert.Equal("Alice", byId!.UserName);

            // 用户名查找不区分大小写
            Assert.NotNull(await _store.FindByUserNameAsync("ALICE"));
            Assert.NotNull(await _store.FindByUserNameAsync("alice"));

            byId.DisplayName = "Alice Z";
            await _store.UpdateAsync(byId);
            Assert.Equal("Alice Z", (await _store.FindByIdAsync("u1"))!.DisplayName);

            Assert.Equal(1, await _store.CountAsync(null));
            IReadOnlyList<AuthUser> list = await _store.ListAsync("ali", 0, 10);
            Assert.Single(list);

            await ((IUserStore)_store).DeleteAsync("u1");
            Assert.Null(await _store.FindByIdAsync("u1"));
            Assert.Null(await _store.FindByUserNameAsync("alice"));
        }

        [Fact]
        public async Task 用户名唯一_不区分大小写()
        {
            await _store.CreateAsync(new AuthUser { Id = "u1", UserName = "Alice" });

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _store.CreateAsync(new AuthUser { Id = "u2", UserName = "ALICE" }));
        }

        [Fact]
        public async Task 用户重命名冲突检测()
        {
            await _store.CreateAsync(new AuthUser { Id = "u1", UserName = "alice" });
            await _store.CreateAsync(new AuthUser { Id = "u2", UserName = "bob" });

            AuthUser bob = (await _store.FindByIdAsync("u2"))!;
            bob.UserName = "Alice";

            await Assert.ThrowsAsync<InvalidOperationException>(() => _store.UpdateAsync(bob));

            // 合法改名后旧名释放
            bob.UserName = "bobby";
            await _store.UpdateAsync(bob);
            Assert.Null(await _store.FindByUserNameAsync("bob"));
            Assert.NotNull(await _store.FindByUserNameAsync("bobby"));
        }

        [Fact]
        public async Task 返回对象深拷贝隔离()
        {
            var user = new AuthUser { Id = "u1", UserName = "alice" };
            user.Roles.Add("admin");
            await _store.CreateAsync(user);

            // 修改传入对象不影响存储
            user.Roles.Add("hacker-in");
            Assert.Single((await _store.FindByIdAsync("u1"))!.Roles);

            // 修改返回对象不影响存储
            AuthUser fetched = (await _store.FindByIdAsync("u1"))!;
            fetched.Roles.Add("hacker-out");
            fetched.UserName = "mallory";

            AuthUser again = (await _store.FindByIdAsync("u1"))!;
            Assert.Equal("alice", again.UserName);
            Assert.Equal(new[] { "admin" }, again.Roles);
        }

        #endregion

        #region 角色

        [Fact]
        public async Task 角色CRUD()
        {
            var role = new AuthRole { Id = "r1", Name = "Editor" };
            role.Permissions.Add("doc.edit");
            await _store.CreateAsync(role);

            IRoleStore roles = _store;
            Assert.NotNull(await roles.FindByIdAsync("r1"));
            Assert.NotNull(await _store.FindByNameAsync("editor")); // 不区分大小写
            Assert.Single(await roles.GetAllAsync());

            AuthRole fetched = (await _store.FindByNameAsync("Editor"))!;
            fetched.Permissions.Add("doc.publish");
            await roles.UpdateAsync(fetched);
            Assert.Equal(2, (await roles.FindByIdAsync("r1"))!.Permissions.Count);

            await roles.DeleteAsync("r1");
            Assert.Null(await roles.FindByIdAsync("r1"));
            Assert.Null(await _store.FindByNameAsync("editor"));
        }

        [Fact]
        public async Task 角色名唯一_不区分大小写()
        {
            await _store.CreateAsync(new AuthRole { Name = "Admin" });

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _store.CreateAsync(new AuthRole { Name = "ADMIN" }));
        }

        [Fact]
        public async Task 系统角色删除抛异常()
        {
            await _store.CreateAsync(new AuthRole { Id = "r1", Name = "sys-admin", IsSystem = true });

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => ((IRoleStore)_store).DeleteAsync("r1"));
            Assert.NotNull(await ((IRoleStore)_store).FindByIdAsync("r1"));
        }

        #endregion

        #region 客户端

        [Fact]
        public async Task 客户端CRUD_与唯一性()
        {
            await _store.CreateAsync(new ClientApplication { ClientId = "cli1", ClientName = "App" });

            Assert.NotNull(await _store.FindByClientIdAsync("cli1"));
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => _store.CreateAsync(new ClientApplication { ClientId = "cli1" }));

            ClientApplication client = (await _store.FindByClientIdAsync("cli1"))!;
            client.Enabled = false;
            await _store.UpdateAsync(client);
            Assert.False((await _store.FindByClientIdAsync("cli1"))!.Enabled);

            await ((IClientStore)_store).DeleteAsync("cli1");
            Assert.Null(await _store.FindByClientIdAsync("cli1"));
        }

        #endregion

        #region 版本号

        [Fact]
        public async Task 版本递增与Changed事件()
        {
            long initial = _store.Version;
            var observed = new List<long>();
            _store.Changed += v => observed.Add(v);

            await _store.CreateAsync(new AuthUser { Id = "u1", UserName = "alice" });
            Assert.Equal(initial + 1, _store.Version);
            Assert.Equal(new[] { initial + 1 }, observed);

            _store.Bump();
            Assert.Equal(initial + 2, _store.Version);
            Assert.Equal(new[] { initial + 1, initial + 2 }, observed);
        }

        [Fact]
        public async Task 令牌写入_不影响版本号()
        {
            long before = _store.Version;

            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord
            {
                TokenHash = "h1",
                SubjectId = "u1",
                ClientId = "app1",
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1),
            });

            Assert.Equal(before, _store.Version);
        }

        #endregion

        #region 授权码与清理

        [Fact]
        public async Task 授权码_只成功消费一次()
        {
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord
            {
                CodeHash = "code1",
                ClientId = "cli1",
                SubjectId = "u1",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            });

            AuthorizationCodeRecord? first = await _store.ConsumeAuthorizationCodeAsync("code1");
            Assert.NotNull(first);
            Assert.NotNull(first!.ConsumedAt);

            Assert.Null(await _store.ConsumeAuthorizationCodeAsync("code1"));
        }

        [Fact]
        public async Task 授权码_过期不返回()
        {
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord
            {
                CodeHash = "expired",
                ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            });

            Assert.Null(await _store.ConsumeAuthorizationCodeAsync("expired"));
        }

        [Fact]
        public async Task CleanupExpired_清理过期令牌与授权码()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord { TokenHash = "old", ExpiresAt = now.AddDays(-1) });
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord { TokenHash = "live", ExpiresAt = now.AddDays(1) });
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord { CodeHash = "old-code", ExpiresAt = now.AddMinutes(-5) });
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord { CodeHash = "live-code", ExpiresAt = now.AddMinutes(5) });

            int removed = await _store.CleanupExpiredAsync(now);

            Assert.Equal(2, removed);
            Assert.Null(await _store.FindRefreshTokenAsync("old"));
            Assert.NotNull(await _store.FindRefreshTokenAsync("live"));
            Assert.NotNull(await _store.ConsumeAuthorizationCodeAsync("live-code"));
        }

        #endregion
    }
}
