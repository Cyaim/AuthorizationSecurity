using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Cluster;
using Cyaim.Authentication.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// EF Core 存储的 DI 装配。
    /// </summary>
    public static class CyaimAuthEntityFrameworkExtensions
    {
        /// <summary>
        /// 用 EF Core 共享数据库存储支撑集群：注册 <see cref="Cyaim.Authentication.EntityFrameworkCore.CyaimAuthDbContext"/> 工厂、
        /// 把 <see cref="EntityFrameworkAuthStore"/> 映射为五个数据存储接口，并以数据库单行计数器
        /// （<see cref="EfClusterVersionStore"/>）作为集群版本启用跨实例缓存失效。
        /// <para>只需一个共享数据库即可组集群，无需 Redis。</para>
        /// </summary>
        /// <param name="builder">核心构建器（来自 AddCyaimAuthentication(...).Core 或 AddCyaimAuthCore(...)）</param>
        /// <param name="configureDb">配置 EF Core 提供程序（如 UseNpgsql/UseSqlServer/UseSqlite）</param>
        /// <param name="configureCluster">配置集群版本轮询（可选）</param>
        public static CyaimAuthCoreBuilder AddCyaimAuthEntityFrameworkStores(
            this CyaimAuthCoreBuilder builder,
            Action<DbContextOptionsBuilder> configureDb,
            Action<ClusterVersionOptions>? configureCluster = null)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }
            if (configureDb == null)
            {
                throw new ArgumentNullException(nameof(configureDb));
            }

            // 上下文工厂（单例）——存储以单例运行、每次操作创建短生命周期上下文，供单例评估器安全使用
            builder.Services.AddDbContextFactory<CyaimAuthDbContext>(configureDb);

            // 数据存储（单例）映射到五个数据接口
            builder.Services.TryAddSingleton<EntityFrameworkAuthStore>();
            builder.MapDataStore<EntityFrameworkAuthStore>();

            // 数据库单行计数器作为集群版本 → 启用跨实例缓存失效
            builder.Services.TryAddSingleton<IClusterVersionStore, EfClusterVersionStore>();
            builder.AddClusterCacheInvalidation<EfClusterVersionStore>(configureCluster);

            return builder;
        }

        /// <summary>
        /// 确保数据库架构存在（开发/演示便捷方法，对空库调用 <c>EnsureCreated</c> 并播下集群版本初始行）。
        /// 已容忍多实例并发首次创建的竞态：若架构已被其他实例建好则视为成功。
        /// <para><b>生产环境请改用 EF Core 迁移</b>，并在扩容前先完成一次迁移，而非让每个实例并发建表。</para>
        /// </summary>
        public static async Task EnsureCyaimAuthDatabaseCreatedAsync(this IServiceProvider services, CancellationToken cancellationToken = default)
        {
            var factory = services.GetRequiredService<IDbContextFactory<CyaimAuthDbContext>>();
            await using CyaimAuthDbContext db = await factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                await db.Database.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // 可能是另一实例正并发创建架构；若架构已就绪则视为成功，否则抛出
                if (!await SchemaExistsAsync(db, cancellationToken).ConfigureAwait(false))
                {
                    throw;
                }
            }

            if (!await db.ClusterVersion.AnyAsync(x => x.Id == 1, cancellationToken).ConfigureAwait(false))
            {
                db.ClusterVersion.Add(new ClusterVersionRow { Id = 1, Version = 0 });
                try
                {
                    await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (DbUpdateException)
                {
                    // 并发实例已初始化，忽略
                }
            }
        }

        private static async Task<bool> SchemaExistsAsync(CyaimAuthDbContext db, CancellationToken ct)
        {
            try
            {
                // 能查询任一表即说明架构已就绪
                await db.ClusterVersion.AnyAsync(ct).ConfigureAwait(false);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
