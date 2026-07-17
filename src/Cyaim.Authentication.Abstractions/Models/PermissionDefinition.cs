using System;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 权限定义：系统中可被授予的权限节点（供管理面板展示与分配）。
    /// </summary>
    public class PermissionDefinition
    {
        /// <summary>权限代码（规范化，如 sys.user.read）</summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>描述</summary>
        public string? Description { get; set; }

        /// <summary>分组（通常为模块名）</summary>
        public string? Group { get; set; }

        /// <summary>定义来源</summary>
        public PermissionOrigin Origin { get; set; } = PermissionOrigin.Manual;

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// 权限定义来源。
    /// </summary>
    public enum PermissionOrigin
    {
        /// <summary>手工创建</summary>
        Manual = 0,
        /// <summary>端点扫描自动发现</summary>
        EndpointDiscovery = 1,
        /// <summary>系统内置</summary>
        System = 2,
    }
}
