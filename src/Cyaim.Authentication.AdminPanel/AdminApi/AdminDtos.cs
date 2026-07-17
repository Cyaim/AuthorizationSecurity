using System;
using System.Collections.Generic;
using System.Linq;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.AdminPanel
{
    /// <summary>
    /// 用户对外安全视图（绝不包含口令哈希与安全戳）。
    /// </summary>
    public sealed class UserDto
    {
        /// <summary>用户Id</summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>登录名</summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>邮箱</summary>
        public string? Email { get; set; }

        /// <summary>是否启用</summary>
        public bool IsEnabled { get; set; }

        /// <summary>锁定截止时间</summary>
        public DateTimeOffset? LockoutEnd { get; set; }

        /// <summary>角色名列表</summary>
        public List<string> Roles { get; set; } = new List<string>();

        /// <summary>直接授予的权限代码</summary>
        public List<string> DirectPermissions { get; set; } = new List<string>();

        /// <summary>直接拒绝的权限代码</summary>
        public List<string> DeniedPermissions { get; set; } = new List<string>();

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; }

        /// <summary>最后修改时间</summary>
        public DateTimeOffset UpdatedAt { get; set; }

        /// <summary>
        /// 从存储模型构建安全视图。
        /// </summary>
        public static UserDto From(AuthUser user) => new UserDto
        {
            Id = user.Id,
            UserName = user.UserName,
            DisplayName = user.DisplayName,
            Email = user.Email,
            IsEnabled = user.IsEnabled,
            LockoutEnd = user.LockoutEnd,
            Roles = new List<string>(user.Roles),
            DirectPermissions = new List<string>(user.DirectPermissions),
            DeniedPermissions = new List<string>(user.DeniedPermissions),
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt,
        };
    }

    /// <summary>
    /// 客户端应用对外安全视图（不包含密钥哈希，仅暴露是否设置了密钥）。
    /// </summary>
    public sealed class ClientDto
    {
        /// <summary>客户端标识</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>客户端名称</summary>
        public string? ClientName { get; set; }

        /// <summary>是否已设置密钥</summary>
        public bool HasSecret { get; set; }

        /// <summary>允许的授权类型</summary>
        public List<string> AllowedGrantTypes { get; set; } = new List<string>();

        /// <summary>允许的回调地址</summary>
        public List<string> RedirectUris { get; set; } = new List<string>();

        /// <summary>登出后允许跳转的地址</summary>
        public List<string> PostLogoutRedirectUris { get; set; } = new List<string>();

        /// <summary>允许申请的作用域</summary>
        public List<string> AllowedScopes { get; set; } = new List<string>();

        /// <summary>客户端凭据模式下授予的权限代码</summary>
        public List<string> Permissions { get; set; } = new List<string>();

        /// <summary>是否强制 PKCE</summary>
        public bool RequirePkce { get; set; }

        /// <summary>是否允许离线访问</summary>
        public bool AllowOfflineAccess { get; set; }

        /// <summary>访问令牌有效期（秒）</summary>
        public int AccessTokenLifetimeSeconds { get; set; }

        /// <summary>刷新令牌有效期（秒）</summary>
        public int RefreshTokenLifetimeSeconds { get; set; }

        /// <summary>授权码有效期（秒）</summary>
        public int AuthorizationCodeLifetimeSeconds { get; set; }

        /// <summary>是否启用</summary>
        public bool Enabled { get; set; }

        /// <summary>允许的 CORS 来源</summary>
        public List<string> AllowedCorsOrigins { get; set; } = new List<string>();

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; }

        /// <summary>最后修改时间</summary>
        public DateTimeOffset UpdatedAt { get; set; }

        /// <summary>
        /// 从存储模型构建安全视图。
        /// </summary>
        public static ClientDto From(ClientApplication client) => new ClientDto
        {
            ClientId = client.ClientId,
            ClientName = client.ClientName,
            HasSecret = !string.IsNullOrEmpty(client.ClientSecretHash),
            AllowedGrantTypes = new List<string>(client.AllowedGrantTypes),
            RedirectUris = new List<string>(client.RedirectUris),
            PostLogoutRedirectUris = new List<string>(client.PostLogoutRedirectUris),
            AllowedScopes = new List<string>(client.AllowedScopes),
            Permissions = new List<string>(client.Permissions),
            RequirePkce = client.RequirePkce,
            AllowOfflineAccess = client.AllowOfflineAccess,
            AccessTokenLifetimeSeconds = client.AccessTokenLifetimeSeconds,
            RefreshTokenLifetimeSeconds = client.RefreshTokenLifetimeSeconds,
            AuthorizationCodeLifetimeSeconds = client.AuthorizationCodeLifetimeSeconds,
            Enabled = client.Enabled,
            AllowedCorsOrigins = new List<string>(client.AllowedCorsOrigins),
            CreatedAt = client.CreatedAt,
            UpdatedAt = client.UpdatedAt,
        };
    }

    /// <summary>创建用户请求。</summary>
    public sealed class CreateUserRequest
    {
        /// <summary>登录名（必填）</summary>
        public string? UserName { get; set; }

        /// <summary>初始密码（必填）</summary>
        public string? Password { get; set; }

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>邮箱</summary>
        public string? Email { get; set; }

        /// <summary>角色名列表</summary>
        public List<string>? Roles { get; set; }

        /// <summary>直接授予的权限代码</summary>
        public List<string>? DirectPermissions { get; set; }

        /// <summary>直接拒绝的权限代码</summary>
        public List<string>? DeniedPermissions { get; set; }
    }

    /// <summary>更新用户请求（null 字段保持不变；不含密码，密码走重置接口）。</summary>
    public sealed class UpdateUserRequest
    {
        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>邮箱</summary>
        public string? Email { get; set; }

        /// <summary>角色名列表</summary>
        public List<string>? Roles { get; set; }

        /// <summary>直接授予的权限代码</summary>
        public List<string>? DirectPermissions { get; set; }

        /// <summary>直接拒绝的权限代码</summary>
        public List<string>? DeniedPermissions { get; set; }

        /// <summary>是否启用</summary>
        public bool? IsEnabled { get; set; }
    }

    /// <summary>重置密码请求。</summary>
    public sealed class ResetPasswordRequest
    {
        /// <summary>新密码（必填）</summary>
        public string? NewPassword { get; set; }
    }

    /// <summary>创建/更新角色请求（更新时 null 字段保持不变）。</summary>
    public sealed class RoleRequest
    {
        /// <summary>角色名（创建时必填）</summary>
        public string? Name { get; set; }

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>描述</summary>
        public string? Description { get; set; }

        /// <summary>父角色名</summary>
        public List<string>? ParentRoles { get; set; }

        /// <summary>允许的权限代码</summary>
        public List<string>? Permissions { get; set; }

        /// <summary>拒绝的权限代码</summary>
        public List<string>? DeniedPermissions { get; set; }

        /// <summary>是否系统内置角色</summary>
        public bool? IsSystem { get; set; }
    }

    /// <summary>权限定义批量登记项。</summary>
    public sealed class PermissionUpsertRequest
    {
        /// <summary>权限代码（必填）</summary>
        public string? Code { get; set; }

        /// <summary>显示名</summary>
        public string? DisplayName { get; set; }

        /// <summary>描述</summary>
        public string? Description { get; set; }

        /// <summary>分组</summary>
        public string? Group { get; set; }
    }

    /// <summary>创建/更新客户端请求（更新时 null 字段保持不变；Secret 语义见各接口说明）。</summary>
    public sealed class ClientRequest
    {
        /// <summary>客户端标识（创建时必填）</summary>
        public string? ClientId { get; set; }

        /// <summary>客户端名称</summary>
        public string? ClientName { get; set; }

        /// <summary>
        /// 客户端密钥明文：创建时有值则哈希存储；
        /// 更新时 null=不变、空串=清除、有值=更新。
        /// </summary>
        public string? Secret { get; set; }

        /// <summary>允许的授权类型</summary>
        public List<string>? AllowedGrantTypes { get; set; }

        /// <summary>允许的回调地址</summary>
        public List<string>? RedirectUris { get; set; }

        /// <summary>登出后允许跳转的地址</summary>
        public List<string>? PostLogoutRedirectUris { get; set; }

        /// <summary>允许申请的作用域</summary>
        public List<string>? AllowedScopes { get; set; }

        /// <summary>客户端凭据模式下授予的权限代码</summary>
        public List<string>? Permissions { get; set; }

        /// <summary>是否强制 PKCE</summary>
        public bool? RequirePkce { get; set; }

        /// <summary>是否允许离线访问</summary>
        public bool? AllowOfflineAccess { get; set; }

        /// <summary>访问令牌有效期（秒）</summary>
        public int? AccessTokenLifetimeSeconds { get; set; }

        /// <summary>刷新令牌有效期（秒）</summary>
        public int? RefreshTokenLifetimeSeconds { get; set; }

        /// <summary>授权码有效期（秒）</summary>
        public int? AuthorizationCodeLifetimeSeconds { get; set; }

        /// <summary>是否启用</summary>
        public bool? Enabled { get; set; }

        /// <summary>允许的 CORS 来源</summary>
        public List<string>? AllowedCorsOrigins { get; set; }
    }
}
