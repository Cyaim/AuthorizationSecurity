using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Cyaim.Authentication.ClusterTests
{
    /// <summary>
    /// EF Core 存储契约测试：验证 EntityFrameworkAuthStore 作为独立存储的 CRUD、唯一性、
    /// 令牌原子消费、授权码一次性、清理，以及数据库集群版本存储的原子递增。用临时 SQLite 文件。
    /// </summary>
    public sealed class EfStoreTests : IDisposable
    {
        private readonly string _dbPath;
        private readonly IDbContextFactory<CyaimAuthDbContext> _factory;
        private readonly EntityFrameworkAuthStore _store;
        private readonly EfClusterVersionStore _version;

        public EfStoreTests()
        {
            _dbPath = Path.Combine(Path.GetTempPath(), "cyaim-ef-" + Guid.NewGuid().ToString("N") + ".db");
            var opts = new DbContextOptionsBuilder<CyaimAuthDbContext>().UseSqlite("Data Source=" + _dbPath).Options;
            _factory = new PooledFactory(opts);
            using (CyaimAuthDbContext db = _factory.CreateDbContext())
            {
                db.Database.EnsureCreated();
            }
            // 存储自身不 Bump 影响测试断言，用一个不做事的版本；集群版本单独测
            _store = new EntityFrameworkAuthStore(_factory, new NoopVersion());
            _version = new EfClusterVersionStore(_factory);
        }

        private sealed class PooledFactory : IDbContextFactory<CyaimAuthDbContext>
        {
            private readonly DbContextOptions<CyaimAuthDbContext> _o;
            public PooledFactory(DbContextOptions<CyaimAuthDbContext> o) => _o = o;
            public CyaimAuthDbContext CreateDbContext() => new CyaimAuthDbContext(_o);
        }

        private sealed class NoopVersion : IAuthStoreVersion
        {
            public long Version => 0;
            public event Action<long>? Changed { add { } remove { } }
            public void Bump() { }
        }

        [Fact]
        public async Task 用户_CRUD_唯一性_大小写不敏感查找()
        {
            await _store.CreateAsync(new AuthUser { Id = "u1", UserName = "Alice", Email = "a@x.com", Roles = { "r1" } });

            AuthUser? byId = await _store.FindByIdAsync("u1");
            Assert.Equal("Alice", byId!.UserName);
            AuthUser? byName = await _store.FindByUserNameAsync("alice"); // 大小写不敏感
            Assert.Equal("u1", byName!.Id);

            // 唯一性：重复用户名 → InvalidOperationException
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                _store.CreateAsync(new AuthUser { Id = "u2", UserName = "alice" }));

            // 更新
            byId.DisplayName = "改名";
            byId.Roles = new List<string> { "r1", "r2" };
            await _store.UpdateAsync(byId);
            AuthUser? updated = await _store.FindByIdAsync("u1");
            Assert.Equal("改名", updated!.DisplayName);
            Assert.Equal(2, updated.Roles.Count);

            // 列表/计数/搜索
            await _store.CreateAsync(new AuthUser { Id = "u3", UserName = "bob" });
            Assert.Equal(2, await _store.CountAsync(null));
            Assert.Equal(1, await _store.CountAsync("bob"));
            IReadOnlyList<AuthUser> list = await _store.ListAsync(null, 0, 10);
            Assert.Equal(2, list.Count);

            // 删除
            await _store.DeleteAsync("u1");
            Assert.Null(await _store.FindByIdAsync("u1"));
        }

        [Fact]
        public async Task 角色_CRUD_系统角色不可删除()
        {
            IRoleStore roles = _store;
            await roles.CreateAsync(new AuthRole { Id = "role1", Name = "admin", IsSystem = true, Permissions = { "a.**" } });
            await roles.CreateAsync(new AuthRole { Id = "role2", Name = "viewer" });

            Assert.Equal(2, (await roles.GetAllAsync()).Count);
            AuthRole? byName = await roles.FindByNameAsync("ADMIN");
            Assert.Equal("role1", byName!.Id);

            await Assert.ThrowsAsync<InvalidOperationException>(() => roles.DeleteAsync("role1")); // 系统角色
            await roles.DeleteAsync("role2");
            Assert.Single(await roles.GetAllAsync());
        }

        [Fact]
        public async Task 客户端与权限定义_CRUD()
        {
            IClientStore clients = _store;
            await clients.CreateAsync(new ClientApplication { ClientId = "web", AllowedGrantTypes = { "authorization_code" }, RedirectUris = { "https://x/cb" } });
            ClientApplication? c = await clients.FindByClientIdAsync("web");
            Assert.Contains("https://x/cb", c!.RedirectUris);
            Assert.Single(await clients.GetAllAsync());

            IPermissionDefinitionStore perms = _store;
            await perms.UpsertAsync(new[]
            {
                new PermissionDefinition { Code = "sys.user.read", DisplayName = "读用户", Group = "用户" },
                new PermissionDefinition { Code = "sys.user.write", Group = "用户" },
            });
            Assert.Equal(2, (await perms.GetAllAsync()).Count);
            // upsert 更新
            await perms.UpsertAsync(new[] { new PermissionDefinition { Code = "sys.user.read", DisplayName = "查看用户" } });
            IReadOnlyList<PermissionDefinition> all = await perms.GetAllAsync();
            Assert.Equal("查看用户", all.First(x => x.Code == "sys.user.read").DisplayName);
            await perms.DeleteAsync("sys.user.write");
            Assert.Single(await perms.GetAllAsync());
        }

        [Fact]
        public async Task 刷新令牌_原子消费_二次消费识别为已消费()
        {
            var now = DateTimeOffset.UtcNow;
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord
            {
                TokenHash = "h1", FamilyId = "f1", SubjectId = "u1", ClientId = "web",
                CreatedAt = now, ExpiresAt = now.AddDays(1),
            });

            RefreshTokenConsumeResult first = await _store.ConsumeRefreshTokenAsync("h1", now);
            Assert.Equal(RefreshTokenConsumeStatus.Consumed, first.Status);

            RefreshTokenConsumeResult second = await _store.ConsumeRefreshTokenAsync("h1", now);
            Assert.Equal(RefreshTokenConsumeStatus.AlreadyConsumed, second.Status);

            Assert.Equal(RefreshTokenConsumeStatus.NotFound, (await _store.ConsumeRefreshTokenAsync("nope", now)).Status);

            // 过期
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord { TokenHash = "h2", ClientId = "web", ExpiresAt = now.AddSeconds(-1) });
            Assert.Equal(RefreshTokenConsumeStatus.Expired, (await _store.ConsumeRefreshTokenAsync("h2", now)).Status);

            // 按客户端吊销
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord { TokenHash = "h3", ClientId = "web", ExpiresAt = now.AddDays(1) });
            await _store.RevokeClientRefreshTokensAsync("web");
            Assert.Equal(RefreshTokenConsumeStatus.Revoked, (await _store.ConsumeRefreshTokenAsync("h3", now)).Status);
        }

        [Fact]
        public async Task 授权码_一次性消费_清理过期()
        {
            var now = DateTimeOffset.UtcNow;
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord
            {
                CodeHash = "c1", ClientId = "web", SubjectId = "u1", RedirectUri = "https://x/cb",
                Scopes = { "openid" }, ExpiresAt = now.AddMinutes(5),
            });

            AuthorizationCodeRecord? consumed = await _store.ConsumeAuthorizationCodeAsync("c1");
            Assert.NotNull(consumed);
            Assert.Equal("u1", consumed!.SubjectId);
            // 二次消费失败
            Assert.Null(await _store.ConsumeAuthorizationCodeAsync("c1"));

            // 清理过期
            await _store.SaveAuthorizationCodeAsync(new AuthorizationCodeRecord { CodeHash = "c2", ClientId = "web", ExpiresAt = now.AddSeconds(-1) });
            await _store.SaveRefreshTokenAsync(new RefreshTokenRecord { TokenHash = "rt-exp", ClientId = "web", ExpiresAt = now.AddSeconds(-1) });
            int cleaned = await _store.CleanupExpiredAsync(now);
            Assert.Equal(2, cleaned); // c2 + rt-exp
        }

        [Fact]
        public async Task 集群版本存储_原子递增与读取()
        {
            long v0 = await _version.ReadAsync();
            long v1 = await _version.IncrementAsync();
            Assert.True(v1 > v0);
            long v2 = await _version.IncrementAsync();
            Assert.Equal(v1 + 1, v2);
            Assert.Equal(v2, await _version.ReadAsync());
        }

        public void Dispose()
        {
            try
            {
                Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
                if (File.Exists(_dbPath))
                {
                    File.Delete(_dbPath);
                }
            }
            catch (IOException) { }
        }
    }
}
