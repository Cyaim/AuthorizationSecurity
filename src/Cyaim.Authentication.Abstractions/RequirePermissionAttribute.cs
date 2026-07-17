using System;

namespace Cyaim.Authentication.Abstractions
{
    /// <summary>
    /// 声明访问目标所需的权限。可标注在控制器/方法/任意成员上；
    /// ASP.NET Core 集成会将其转换为端点元数据，桌面应用可用于 UI 权限门控。
    /// 多个特性之间为“且”关系；单个特性内多个代码默认“或”（<see cref="RequireAll"/> 可改为“且”）。
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Field,
        AllowMultiple = true, Inherited = true)]
    public class RequirePermissionAttribute : Attribute
    {
        /// <summary>
        /// 要求指定权限。
        /// </summary>
        /// <param name="permissionCodes">权限代码；为空时表示仅要求已认证</param>
        public RequirePermissionAttribute(params string[] permissionCodes)
        {
            PermissionCodes = permissionCodes ?? Array.Empty<string>();
        }

        /// <summary>要求的权限代码</summary>
        public string[] PermissionCodes { get; }

        /// <summary>true 要求全部满足；false（默认）满足任一即可</summary>
        public bool RequireAll { get; set; }

        /// <summary>附加 ABAC 策略名（与权限代码同时要求）</summary>
        public string? Policy { get; set; }
    }

    /// <summary>
    /// 允许游客（未认证主体）访问目标，覆盖上层的权限要求。
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class AllowGuestAttribute : Attribute
    {
    }
}
