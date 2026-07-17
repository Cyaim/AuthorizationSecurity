using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 角色（RBAC）。支持层级继承：角色继承其父角色的允许与拒绝权限（NIST RBAC1）。
    /// </summary>
    public class AuthRole
    {
        /// <summary>角色唯一标识</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>角色名（唯一，不区分大小写）</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>描述</summary>
        public string? Description { get; set; }

        /// <summary>父角色名（继承其权限；环将被安全忽略）</summary>
        public List<string> ParentRoles { get; set; } = new List<string>();

        /// <summary>允许的权限代码</summary>
        public List<string> Permissions { get; set; } = new List<string>();

        /// <summary>拒绝的权限代码（优先于任何允许）</summary>
        public List<string> DeniedPermissions { get; set; } = new List<string>();

        /// <summary>系统内置角色不可删除</summary>
        public bool IsSystem { get; set; }

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>最后修改时间</summary>
        public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 深拷贝（集合独立），用于存储读写隔离——比 JSON 往返快约一个数量级。
        /// </summary>
        public AuthRole Clone() => new AuthRole
        {
            Id = Id,
            Name = Name,
            DisplayName = DisplayName,
            Description = Description,
            ParentRoles = new List<string>(ParentRoles),
            Permissions = new List<string>(Permissions),
            DeniedPermissions = new List<string>(DeniedPermissions),
            IsSystem = IsSystem,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
        };
    }
}
