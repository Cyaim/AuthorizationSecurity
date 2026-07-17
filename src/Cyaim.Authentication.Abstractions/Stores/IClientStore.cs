using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 客户端应用存储。
    /// </summary>
    public interface IClientStore
    {
        /// <summary>按客户端Id查找</summary>
        Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);

        /// <summary>获取全部客户端</summary>
        Task<IReadOnlyList<ClientApplication>> GetAllAsync(CancellationToken cancellationToken = default);

        /// <summary>创建客户端</summary>
        Task CreateAsync(ClientApplication client, CancellationToken cancellationToken = default);

        /// <summary>更新客户端</summary>
        Task UpdateAsync(ClientApplication client, CancellationToken cancellationToken = default);

        /// <summary>删除客户端</summary>
        Task DeleteAsync(string clientId, CancellationToken cancellationToken = default);
    }
}
