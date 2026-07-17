using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Cluster;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// 集群缓存失效验证：证明任一实例的授权变更经共享版本传播到其他实例，使其权限集缓存失效重建。
    /// 用进程内共享计数器模拟 Redis/DB 的 IClusterVersionStore，用共享 InMemoryAuthStore 模拟共享数据库。
    /// 关闭轮询定时器、用不推进的 FakeClock 隔离 TTL，专测"版本驱动"的跨实例失效。
    /// </summary>
    public class ClusterCacheInvalidationTests
    {
        /// <summary>进程内共享的集群版本存储（模拟 Redis INCR）。</summary>
        private sealed class SharedVersionStore : IClusterVersionStore
        {
            private long _v;
            public Task<long> ReadAsync(CancellationToken ct = default) => Task.FromResult(Interlocked.Read(ref _v));
            public Task<long> IncrementAsync(CancellationToken ct = default) => Task.FromResult(Interlocked.Increment(ref _v));
        }

        [Fact]
        public async Task ClusterVersion_两实例经共享存储同步版本()
        {
            var shared = new SharedVersionStore();
            using var verA = new ClusterAuthStoreVersion(shared, new ClusterVersionOptions { RefreshInterval = TimeSpan.Zero });
            using var verB = new ClusterAuthStoreVersion(shared, new ClusterVersionOptions { RefreshInterval = TimeSpan.Zero });

            long changedB = -1;
            verB.Changed += v => changedB = v;

            long start = verA.Version;
            Assert.Equal(start, verB.Version);

            // A 递增（模拟本实例写数据后调用；用可等待版本确保共享计数器已递增）
            await verA.BumpAsync();
            Assert.True(verA.Version > start); // A 本地即时失效

            // B 尚未刷新，仍是旧版本
            Assert.Equal(start, verB.Version);

            // B 轮询（后台定时器在生产中自动做，测试手动触发）
            await verB.RefreshAsync();
            Assert.Equal(verA.Version, verB.Version); // B 追上
            Assert.Equal(verB.Version, changedB);     // 触发了 Changed

            // 单调不回退：再次刷新不改变
            long v = verB.Version;
            await verB.RefreshAsync();
            Assert.Equal(v, verB.Version);
        }

        [Fact]
        public async Task 实例A改角色权限_实例B刷新后失效并读到新权限()
        {
            // 共享"数据库"与共享"Redis"
            var data = new InMemoryAuthStore();
            var shared = new SharedVersionStore();

            await data.CreateAsync(new AuthRole { Name = "r", Permissions = { "demo.read" } });
            await ((IUserStore)data).CreateAsync(new AuthUser { Id = "u1", UserName = "u1", Roles = { "r" } });

            var clockA = new FakeClock();
            var clockB = new FakeClock();
            using ServiceProvider spA = BuildInstance(data, shared, clockA, out ClusterAuthStoreVersion verA);
            using ServiceProvider spB = BuildInstance(data, shared, clockB, out ClusterAuthStoreVersion verB);

            var evalA = spA.GetRequiredService<IPermissionEvaluator>();
            var evalB = spB.GetRequiredService<IPermissionEvaluator>();
            var subject = new AuthSubject { Id = "u1", IsAuthenticated = true, Roles = new[] { "r" } };
            var read = PermissionQuery.Parse("demo.read");
            var write = PermissionQuery.Parse("demo.write");

            // 两实例初始：有 read、无 write（各自缓存）
            Assert.True((await evalA.EvaluateAsync(subject, read)).IsGranted);
            Assert.False((await evalA.EvaluateAsync(subject, write)).IsGranted);
            Assert.True((await evalB.EvaluateAsync(subject, read)).IsGranted);
            Assert.False((await evalB.EvaluateAsync(subject, write)).IsGranted);

            // 实例 A 修改共享数据：角色改为拥有 write（去掉 read），并 Bump 集群版本（模拟分布式存储写后广播）
            AuthRole role = (await data.FindByNameAsync("r"))!;
            role.Permissions = new List<string> { "demo.write" };
            await data.UpdateAsync(role);
            await verA.BumpAsync();

            // 实例 A 立即失效重建 → 读到 write、失去 read
            Assert.True((await evalA.EvaluateAsync(subject, write)).IsGranted);
            Assert.False((await evalA.EvaluateAsync(subject, read)).IsGranted);

            // 实例 B 尚未轮询 → 仍是旧缓存（陈旧）
            Assert.True((await evalB.EvaluateAsync(subject, read)).IsGranted);
            Assert.False((await evalB.EvaluateAsync(subject, write)).IsGranted);

            // 实例 B 轮询共享版本 → 失效重建 → 也读到 write、失去 read
            await verB.RefreshAsync();
            Assert.True((await evalB.EvaluateAsync(subject, write)).IsGranted);
            Assert.False((await evalB.EvaluateAsync(subject, read)).IsGranted);
        }

        private static ServiceProvider BuildInstance(
            InMemoryAuthStore sharedData, IClusterVersionStore sharedVersion, FakeClock clock,
            out ClusterAuthStoreVersion version)
        {
            var services = new ServiceCollection();
            services.AddSingleton<IAuthClock>(clock); // 先注册，AddCyaimAuthCore 的 TryAdd 不覆盖
            services.AddSingleton(sharedData);
            services.AddCyaimAuthCore()
                .MapDataStore<InMemoryAuthStore>()
                .AddClusterCacheInvalidation(sharedVersion, o => o.RefreshInterval = TimeSpan.Zero);
            ServiceProvider sp = services.BuildServiceProvider();
            version = sp.GetRequiredService<ClusterAuthStoreVersion>();
            return sp;
        }
    }
}
