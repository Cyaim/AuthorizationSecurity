using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 已注册的客户端应用（OAuth 2.0 Client, RFC 6749 §2）。
    /// </summary>
    public class ClientApplication
    {
        /// <summary>客户端标识</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>客户端名称（授权页展示）</summary>
        public string? ClientName { get; set; }

        /// <summary>客户端密钥哈希（由 IPasswordHasher 生成；公共客户端可为空）</summary>
        public string? ClientSecretHash { get; set; }

        /// <summary>允许的授权类型（authorization_code / client_credentials / password / refresh_token）</summary>
        public List<string> AllowedGrantTypes { get; set; } = new List<string>();

        /// <summary>允许的回调地址（授权码模式，精确匹配）</summary>
        public List<string> RedirectUris { get; set; } = new List<string>();

        /// <summary>登出后允许跳转的地址</summary>
        public List<string> PostLogoutRedirectUris { get; set; } = new List<string>();

        /// <summary>允许申请的作用域</summary>
        public List<string> AllowedScopes { get; set; } = new List<string>();

        /// <summary>授权码模式是否强制 PKCE（RFC 7636），公共客户端应为 true</summary>
        public bool RequirePkce { get; set; } = true;

        /// <summary>是否允许离线访问（签发刷新令牌）</summary>
        public bool AllowOfflineAccess { get; set; }

        /// <summary>客户端凭据模式下授予客户端主体的权限代码</summary>
        public List<string> Permissions { get; set; } = new List<string>();

        /// <summary>访问令牌有效期（秒），默认 1 小时</summary>
        public int AccessTokenLifetimeSeconds { get; set; } = 3600;

        /// <summary>刷新令牌有效期（秒），默认 14 天</summary>
        public int RefreshTokenLifetimeSeconds { get; set; } = 14 * 24 * 3600;

        /// <summary>授权码有效期（秒），默认 5 分钟</summary>
        public int AuthorizationCodeLifetimeSeconds { get; set; } = 300;

        /// <summary>是否启用</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// 允许的 CORS 来源（浏览器客户端）。此字段仅记录声明，框架自身不下发 CORS 响应头；
        /// 浏览器跨源访问请在宿主用 ASP.NET Core 的 AddCors/UseCors 配置（可读取本字段作为白名单来源）。
        /// </summary>
        public List<string> AllowedCorsOrigins { get; set; } = new List<string>();

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>最后修改时间</summary>
        public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
    }
}
