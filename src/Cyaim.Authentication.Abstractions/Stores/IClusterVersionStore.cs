using System.Threading;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 集群共享的"授权数据版本"来源：一个全集群单调递增的计数器。
    /// <para>
    /// 多实例部署时，任一实例修改用户/角色/权限后需让**所有**实例的权限集缓存失效。
    /// 本接口把"当前版本"与"递增版本"抽象为对共享存储（如 Redis <c>INCR</c> 或数据库单行）的两次操作，
    /// 框架的 <c>ClusterAuthStoreVersion</c> 据此在各实例间同步版本、驱动缓存失效。
    /// </para>
    /// <para>实现应保证 <see cref="IncrementAsync"/> 原子递增；<see cref="ReadAsync"/> 返回最新值。</para>
    /// </summary>
    public interface IClusterVersionStore
    {
        /// <summary>读取当前集群版本。</summary>
        Task<long> ReadAsync(CancellationToken cancellationToken = default);

        /// <summary>原子递增集群版本并返回递增后的新值。</summary>
        Task<long> IncrementAsync(CancellationToken cancellationToken = default);
    }
}
