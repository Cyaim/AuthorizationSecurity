using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.EntityFrameworkCore;

namespace Cyaim.Authentication.EntityFrameworkCore
{
    /// <summary>
    /// 基于数据库单行计数器的集群版本存储：把"授权数据版本"落在共享数据库的一行里，
    /// 用条件 <c>UPDATE ... SET Version = Version + 1</c> 原子递增。因此集群**只需共享数据库**、
    /// 无需 Redis 等额外中间件即可实现跨实例缓存失效。
    /// </summary>
    public class EfClusterVersionStore : IClusterVersionStore
    {
        private readonly IDbContextFactory<CyaimAuthDbContext> _factory;

        /// <summary>创建版本存储。</summary>
        public EfClusterVersionStore(IDbContextFactory<CyaimAuthDbContext> factory)
        {
            _factory = factory;
        }

        /// <inheritdoc/>
        public async Task<long> ReadAsync(CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            ClusterVersionRow? row = await db.ClusterVersion.AsNoTracking()
                .FirstOrDefaultAsync(x => x.Id == 1, cancellationToken).ConfigureAwait(false);
            return row?.Version ?? 0;
        }

        /// <inheritdoc/>
        public async Task<long> IncrementAsync(CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            // 原子条件递增；若单行尚不存在则插入初值 1 后重试
            int affected = await db.ClusterVersion.Where(x => x.Id == 1)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.Version, x => x.Version + 1), cancellationToken)
                .ConfigureAwait(false);

            if (affected == 0)
            {
                await EnsureRowAsync(db, cancellationToken).ConfigureAwait(false);
                await db.ClusterVersion.Where(x => x.Id == 1)
                    .ExecuteUpdateAsync(s => s.SetProperty(x => x.Version, x => x.Version + 1), cancellationToken)
                    .ConfigureAwait(false);
            }

            ClusterVersionRow? row = await db.ClusterVersion.AsNoTracking()
                .FirstOrDefaultAsync(x => x.Id == 1, cancellationToken).ConfigureAwait(false);
            return row?.Version ?? 0;
        }

        private static async Task EnsureRowAsync(CyaimAuthDbContext db, CancellationToken ct)
        {
            bool exists = await db.ClusterVersion.AnyAsync(x => x.Id == 1, ct).ConfigureAwait(false);
            if (!exists)
            {
                db.ClusterVersion.Add(new ClusterVersionRow { Id = 1, Version = 0 });
                try
                {
                    await db.SaveChangesAsync(ct).ConfigureAwait(false);
                }
                catch (DbUpdateException)
                {
                    // 另一实例已插入，忽略
                }
            }
        }
    }
}
