using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 权限定义存储（管理面板的权限清单来源）。
    /// </summary>
    public interface IPermissionDefinitionStore
    {
        /// <summary>批量登记权限定义（存在则更新显示信息，不覆盖手工修改的来源）</summary>
        Task UpsertAsync(IEnumerable<PermissionDefinition> definitions, CancellationToken cancellationToken = default);

        /// <summary>获取全部权限定义</summary>
        Task<IReadOnlyList<PermissionDefinition>> GetAllAsync(CancellationToken cancellationToken = default);

        /// <summary>删除权限定义</summary>
        Task DeleteAsync(string code, CancellationToken cancellationToken = default);
    }
}
