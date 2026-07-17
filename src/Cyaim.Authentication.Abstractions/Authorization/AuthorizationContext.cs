using System;
using System.Collections.Generic;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Authorization
{
    /// <summary>
    /// 鉴权上下文：ABAC 策略评估时可用的属性集合。
    /// </summary>
    public class AuthorizationContext
    {
        /// <summary>被判断的主体</summary>
        public AuthSubject Subject { get; set; } = AuthSubject.Guest();

        /// <summary>正在判断的权限代码（若有）</summary>
        public string? PermissionCode { get; set; }

        /// <summary>资源与环境属性（如 resource.ownerId、request.path）</summary>
        public IDictionary<string, object?> Items { get; } = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        /// <summary>宿主原生上下文（ASP.NET Core 下为 HttpContext），策略可自行转换</summary>
        public object? UnderlyingContext { get; set; }

        /// <summary>评估时刻（UTC）</summary>
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// ABAC 策略：命名的自定义授权规则，可与权限代码组合使用。
    /// 实现应为无状态可并发。
    /// </summary>
    public interface IAuthPolicy
    {
        /// <summary>策略名（唯一，不区分大小写）</summary>
        string Name { get; }

        /// <summary>
        /// 评估策略是否满足。
        /// </summary>
        System.Threading.Tasks.Task<bool> EvaluateAsync(AuthorizationContext context, System.Threading.CancellationToken cancellationToken = default);
    }
}
