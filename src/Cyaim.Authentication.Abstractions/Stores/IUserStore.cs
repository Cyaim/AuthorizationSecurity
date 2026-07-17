using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 用户存储。实现需保证 UserName 唯一（不区分大小写）。
    /// </summary>
    public interface IUserStore
    {
        /// <summary>按Id查找用户</summary>
        Task<AuthUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>按登录名查找用户（不区分大小写）</summary>
        Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default);

        /// <summary>创建用户</summary>
        Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default);

        /// <summary>更新用户</summary>
        Task UpdateAsync(AuthUser user, CancellationToken cancellationToken = default);

        /// <summary>删除用户</summary>
        Task DeleteAsync(string id, CancellationToken cancellationToken = default);

        /// <summary>分页列出用户（search 匹配用户名/显示名/邮箱）</summary>
        Task<IReadOnlyList<AuthUser>> ListAsync(string? search, int skip, int take, CancellationToken cancellationToken = default);

        /// <summary>统计用户数</summary>
        Task<int> CountAsync(string? search, CancellationToken cancellationToken = default);
    }
}
