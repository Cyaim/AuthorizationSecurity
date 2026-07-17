using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cyaim.Authentication.Core.Cluster
{
    /// <summary>
    /// 集群感知的授权数据版本。把一个本地缓存的 <see cref="Version"/>（热路径零开销的 <c>long</c> 读取）
    /// 与集群共享的 <see cref="IClusterVersionStore"/> 保持同步：
    /// <list type="bullet">
    /// <item>本实例修改数据 → <see cref="Bump"/> 递增共享计数器并即时更新本地版本；</item>
    /// <item>其他实例修改数据 → 后台按 <see cref="ClusterVersionOptions.RefreshInterval"/> 轮询共享计数器，
    /// 发现变化即更新本地版本并触发 <see cref="Changed"/>，使本实例的权限集缓存在下次判断时重建。</item>
    /// </list>
    /// 由此，任一实例的授权变更会在"轮询间隔"内传播到全集群（间隔外仍有权限集 TTL 兜底）。
    /// 替代内置 <c>InMemoryAuthStore</c> 的本地 <see cref="IAuthStoreVersion"/> 注册即可让缓存失效跨实例生效。
    /// </summary>
    public sealed class ClusterAuthStoreVersion : IAuthStoreVersion, IDisposable
    {
        private readonly IClusterVersionStore _store;
        private readonly ILogger<ClusterAuthStoreVersion> _logger;
        private readonly Timer? _timer;
        private long _version;
        private int _refreshing;
        private volatile bool _disposed;

        /// <summary>
        /// 创建集群版本同步器。构造后立即读取一次共享版本作为初值；若配置了 <see cref="ClusterVersionOptions.RefreshInterval"/> 则启动后台轮询。
        /// </summary>
        public ClusterAuthStoreVersion(
            IClusterVersionStore store,
            ClusterVersionOptions? options = null,
            ILogger<ClusterAuthStoreVersion>? logger = null)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _logger = logger ?? NullLogger<ClusterAuthStoreVersion>.Instance;
            options ??= new ClusterVersionOptions();

            // 初值：尽力读取共享版本（失败则从 0 起步，靠后续轮询纠正）
            try
            {
                _version = _store.ReadAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "初始化集群版本失败，暂以 0 起步，稍后轮询纠正");
                _version = 0;
            }

            if (options.RefreshInterval > TimeSpan.Zero)
            {
                _timer = new Timer(_ => _ = RefreshAsync(), null, options.RefreshInterval, options.RefreshInterval);
            }
        }

        /// <inheritdoc/>
        public long Version => Interlocked.Read(ref _version);

        /// <inheritdoc/>
        public event Action<long>? Changed;

        /// <inheritdoc/>
        public void Bump()
        {
            // IAuthStoreVersion.Bump 是同步 void：本地乐观自增保证本实例即时失效，
            // 共享计数器的递增（供其他实例轮询感知）后台进行，不阻塞存储写路径。
            long optimistic = Interlocked.Increment(ref _version);
            RaiseChanged(optimistic);
            _ = IncrementSharedAsync();
        }

        /// <summary>
        /// 可等待的递增：本地即时自增 + **等待**共享计数器递增完成。存储在异步写操作中调用它，
        /// 可确保方法返回时其他实例下一次轮询即能看到本次变更（比 <see cref="Bump"/> 更强的传播保证）。
        /// </summary>
        public async Task BumpAsync(CancellationToken cancellationToken = default)
        {
            long optimistic = Interlocked.Increment(ref _version);
            RaiseChanged(optimistic);
            await IncrementSharedAsync(cancellationToken).ConfigureAwait(false);
        }

        private async Task IncrementSharedAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                long shared = await _store.IncrementAsync(cancellationToken).ConfigureAwait(false);
                ApplyRemote(shared);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "递增集群版本失败，本实例已本地失效，跨实例传播将依赖下次轮询");
            }
        }

        /// <summary>
        /// 立即从共享存储刷新一次版本（后台轮询亦调用之；测试可手动调用以确定性验证）。
        /// </summary>
        public async Task RefreshAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed || Interlocked.Exchange(ref _refreshing, 1) == 1)
            {
                return; // 避免轮询重入
            }
            try
            {
                long shared = await _store.ReadAsync(cancellationToken).ConfigureAwait(false);
                ApplyRemote(shared);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "刷新集群版本失败，沿用当前本地版本");
            }
            finally
            {
                Interlocked.Exchange(ref _refreshing, 0);
            }
        }

        // 用共享值推进本地版本（单调不回退），变化时触发 Changed
        private void ApplyRemote(long shared)
        {
            while (true)
            {
                long local = Interlocked.Read(ref _version);
                if (shared <= local)
                {
                    return; // 本地已不落后，不回退
                }
                if (Interlocked.CompareExchange(ref _version, shared, local) == local)
                {
                    RaiseChanged(shared);
                    return;
                }
            }
        }

        private void RaiseChanged(long version)
        {
            try
            {
                Changed?.Invoke(version);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "集群版本 Changed 事件处理器异常");
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _disposed = true;
            _timer?.Dispose();
        }
    }

    /// <summary>
    /// 集群版本同步配置。
    /// </summary>
    public sealed class ClusterVersionOptions
    {
        /// <summary>
        /// 后台轮询共享版本的间隔，决定其他实例的授权变更传播到本实例的最大延迟。
        /// 默认 5 秒；设为 <see cref="TimeSpan.Zero"/> 或负值可关闭轮询（仅用 Bump 的本地即时失效，
        /// 适合有推送式失效背板、或只有单写入实例的场景）。
        /// </summary>
        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromSeconds(5);
    }
}
