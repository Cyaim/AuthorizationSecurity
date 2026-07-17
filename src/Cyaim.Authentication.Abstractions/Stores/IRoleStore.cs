using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 角色存储。实现需保证 Name 唯一（不区分大小写）。
    /// </summary>
    public interface IRoleStore
    {
        /// <summary>按Id查找角色</summary>
        Task<AuthRole?> FindByIdAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>按名称查找角色（不区分大小写）</summary>
        Task<AuthRole?> FindByNameAsync(string name, CancellationToken cancellationToken = default);

        /// <summary>获取全部角色（角色数量通常有限，权限集编译需要全量层级）</summary>
        Task<IReadOnlyList<AuthRole>> GetAllAsync(CancellationToken cancellationToken = default);

        /// <summary>创建角色</summary>
        Task CreateAsync(AuthRole role, CancellationToken cancellationToken = default);

        /// <summary>更新角色</summary>
        Task UpdateAsync(AuthRole role, CancellationToken cancellationToken = default);

        /// <summary>删除角色</summary>
        Task DeleteAsync(string id, CancellationToken cancellationToken = default);
    }
}
