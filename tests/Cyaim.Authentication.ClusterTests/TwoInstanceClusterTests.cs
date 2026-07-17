using System;
using System.IO;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Cluster;
using Cyaim.Authentication.Core.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Cyaim.Authentication.ClusterTests
{
    /// <summary>
    /// 生产集群验证：两个独立"实例"（各自的 ServiceProvider、评估器、令牌管理器、集群版本）共享**同一个
    /// SQLite 数据库文件**（模拟生产中的共享数据库）。证明集群三大关键行为：
    /// 1. 共享数据可见性——实例 A 写、实例 B 读到；
    /// 2. 令牌一次性消费的跨实例原子性——A 轮换后旧令牌在 B 上重放被拦截；
    /// 3. 权限变更的跨实例缓存失效——A 改角色权限（递增数据库集群版本），B 轮询后失效重建读到新权限。
    /// 仅共享一个数据库、无 Redis。
    /// </summary>
    public sealed class TwoInstanceClusterTests : IDisposable
    {
        private readonly string _dbPath;
        private readonly string _conn;

        public TwoInstanceClusterTests()
        {
            _dbPath = Path.Combine(Path.GetTempPath(), "cyaim-cluster-" + Guid.NewGuid().ToString("N") + ".db");
            _conn = "Data Source=" + _dbPath;
        }

        private ServiceProvider BuildInstance()
        {
            var services = new ServiceCollection();
            services.AddCyaimAuthCore(o =>
                {
                    o.Issuer = "cluster-test";
                    o.Audience = "cluster-api";
                    o.HmacSigningKey = "cluster-test-shared-signing-key-32b!!"; // 所有实例共享
                })
                .AddCyaimAuthEntityFrameworkStores(
                    db => db.UseSqlite(_conn),
                    cluster => cluster.RefreshInterval = TimeSpan.Zero); // 测试手动刷新，确定性
            return services.BuildServiceProvider();
        }

        [Fact]
        public async Task 两实例共享数据库_数据可见性_令牌原子消费_缓存失效()
        {
            using ServiceProvider instanceA = BuildInstance();
            using ServiceProvider instanceB = BuildInstance();

            // 由实例 A 建库并播种
            await instanceA.EnsureCyaimAuthDatabaseCreatedAsync();

            var usersA = instanceA.GetRequiredService<IUserStore>();
            var rolesA = instanceA.GetRequiredService<IRoleStore>();
            await rolesA.CreateAsync(new AuthRole { Name = "editor", Permissions = { "doc.read", "doc.write" } });
            await usersA.CreateAsync(new AuthUser { Id = "u1", UserName = "alice", Roles = { "editor" } });

            // ---- 1. 共享数据可见性：实例 B 读到 A 写的数据 ----
            var usersB = instanceB.GetRequiredService<IUserStore>();
            AuthUser? seenByB = await usersB.FindByUserNameAsync("alice");
            Assert.NotNull(seenByB);
            Assert.Equal("u1", seenByB!.Id);

            var evalA = instanceA.GetRequiredService<IPermissionEvaluator>();
            var evalB = instanceB.GetRequiredService<IPermissionEvaluator>();
            var subject = new AuthSubject { Id = "u1", IsAuthenticated = true, Roles = new[] { "editor" } };
            var read = PermissionQuery.Parse("doc.read");
            var delete = PermissionQuery.Parse("doc.delete");

            Assert.True((await evalA.EvaluateAsync(subject, read)).IsGranted);
            Assert.True((await evalB.EvaluateAsync(subject, read)).IsGranted);   // B 经共享库读到角色权限
            Assert.False((await evalB.EvaluateAsync(subject, delete)).IsGranted);

            // ---- 2. 令牌一次性消费跨实例原子性：A 轮换，B 重放旧令牌被拦截 ----
            var mgrA = instanceA.GetRequiredService<RefreshTokenManager>();
            var mgrB = instanceB.GetRequiredService<RefreshTokenManager>();
            (string token, _) = await mgrA.IssueAsync("u1", "web", new[] { "permissions" });

            // A 兑换成功（原子消费共享库中的令牌，签发同家族新令牌）
            RefreshExchangeResult first = await mgrA.ExchangeAsync(token, "web");
            Assert.True(first.Success);

            // B 用同一个（已被 A 消费的）旧令牌兑换 → 检测到重放 → 失败并吊销家族
            RefreshExchangeResult replay = await mgrB.ExchangeAsync(token, "web");
            Assert.False(replay.Success);
            Assert.True(replay.ReplayDetected);

            // 家族已吊销：A 刚拿到的新令牌在任一实例都不可用
            RefreshExchangeResult afterRevoke = await mgrA.ExchangeAsync(first.NewToken!, "web");
            Assert.False(afterRevoke.Success);

            // ---- 3. 权限变更跨实例缓存失效：A 改角色，B 轮询后读到新权限 ----
            AuthRole role = (await rolesA.FindByNameAsync("editor"))!;
            role.Permissions = new System.Collections.Generic.List<string> { "doc.read", "doc.write", "doc.delete" };
            await rolesA.UpdateAsync(role); // EF 存储写后 Bump 集群版本（递增数据库单行）

            // 实例 A 立即失效重建 → 读到新增的 delete
            Assert.True((await evalA.EvaluateAsync(subject, delete)).IsGranted);

            // 实例 B 尚未轮询 → 仍是旧缓存（无 delete）
            Assert.False((await evalB.EvaluateAsync(subject, delete)).IsGranted);

            // 实例 B 轮询数据库集群版本 → 发现变化 → 失效重建 → 读到 delete
            await instanceB.GetRequiredService<ClusterAuthStoreVersion>().RefreshAsync();
            Assert.True((await evalB.EvaluateAsync(subject, delete)).IsGranted);
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
