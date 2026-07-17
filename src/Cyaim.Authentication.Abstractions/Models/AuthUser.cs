using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 存储中的用户账户。
    /// </summary>
    public class AuthUser
    {
        /// <summary>用户唯一标识</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>登录名（唯一，不区分大小写）</summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>邮箱</summary>
        public string? Email { get; set; }

        /// <summary>口令哈希（由 IPasswordHasher 生成，含盐与参数）</summary>
        public string? PasswordHash { get; set; }

        /// <summary>是否启用；禁用后无法登录、令牌自省失败</summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>锁定截止时间（暴力破解防护）</summary>
        public DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>连续登录失败次数</summary>
        public int AccessFailedCount { get; set; }

        /// <summary>安全戳：修改口令/权限重大变更时更新，使已签发令牌失效</summary>
        public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>角色名列表</summary>
        public List<string> Roles { get; set; } = new List<string>();

        /// <summary>直接授予的权限代码</summary>
        public List<string> DirectPermissions { get; set; } = new List<string>();

        /// <summary>直接拒绝的权限代码（优先于任何允许）</summary>
        public List<string> DeniedPermissions { get; set; } = new List<string>();

        /// <summary>附加声明（写入令牌与 ABAC 上下文）</summary>
        public Dictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>最后修改时间</summary>
        public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// 是否处于锁定状态。
        /// </summary>
        public bool IsLockedOut(DateTimeOffset now) => LockoutEnd.HasValue && LockoutEnd.Value > now;

        /// <summary>
        /// 深拷贝（集合与字典独立），用于存储读写隔离——比 JSON 往返快约一个数量级。
        /// </summary>
        public AuthUser Clone() => new AuthUser
        {
            Id = Id,
            UserName = UserName,
            DisplayName = DisplayName,
            Email = Email,
            PasswordHash = PasswordHash,
            IsEnabled = IsEnabled,
            LockoutEnd = LockoutEnd,
            AccessFailedCount = AccessFailedCount,
            SecurityStamp = SecurityStamp,
            Roles = new List<string>(Roles),
            DirectPermissions = new List<string>(DirectPermissions),
            DeniedPermissions = new List<string>(DeniedPermissions),
            Claims = new Dictionary<string, string>(Claims),
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt,
        };
    }
}
