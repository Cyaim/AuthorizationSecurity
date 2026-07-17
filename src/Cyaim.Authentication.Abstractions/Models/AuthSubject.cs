using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 鉴权主体：一次权限判断的对象（用户、客户端应用或游客）。
    /// 由令牌/会话解析得到，不含凭据信息。
    /// </summary>
    public class AuthSubject
    {
        /// <summary>主体唯一标识（用户Id或客户端Id）</summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>显示名称</summary>
        public string? Name { get; set; }

        /// <summary>是否已通过身份认证（游客为 false）</summary>
        public bool IsAuthenticated { get; set; }

        /// <summary>主体类型</summary>
        public AuthSubjectType SubjectType { get; set; } = AuthSubjectType.User;

        /// <summary>所属角色名</summary>
        public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();

        /// <summary>直接授予的权限代码（来自令牌 perm 声明或存储）</summary>
        public IReadOnlyList<string> DirectPermissions { get; set; } = Array.Empty<string>();

        /// <summary>直接拒绝的权限代码</summary>
        public IReadOnlyList<string> DeniedPermissions { get; set; } = Array.Empty<string>();

        /// <summary>令牌作用域</summary>
        public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();

        /// <summary>发起请求的客户端Id（用户经某应用登录时）</summary>
        public string? ClientId { get; set; }

        /// <summary>会话Id（SSO 会话）</summary>
        public string? SessionId { get; set; }

        /// <summary>附加声明（ABAC 属性来源之一）</summary>
        public IReadOnlyDictionary<string, string> Claims { get; set; } = EmptyClaims;

        private static readonly IReadOnlyDictionary<string, string> EmptyClaims =
            new Dictionary<string, string>(0);

        /// <summary>
        /// 创建游客主体。
        /// </summary>
        public static AuthSubject Guest(IReadOnlyList<string>? guestRoles = null) => new AuthSubject
        {
            Id = AuthConstants.GuestSubjectId,
            Name = "Guest",
            IsAuthenticated = false,
            SubjectType = AuthSubjectType.Guest,
            Roles = guestRoles ?? Array.Empty<string>(),
        };
    }

    /// <summary>
    /// 主体类型。
    /// </summary>
    public enum AuthSubjectType
    {
        /// <summary>用户</summary>
        User = 0,
        /// <summary>客户端应用（client_credentials）</summary>
        Client = 1,
        /// <summary>未认证游客</summary>
        Guest = 2,
    }
}
