using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 刷新令牌记录。存储的是令牌的哈希（SHA-256），明文只出现在签发响应中。
    /// 支持轮换：使用后签发新令牌并标记本条已消费；重放已消费令牌将吊销整个家族。
    /// </summary>
    public class RefreshTokenRecord
    {
        /// <summary>令牌哈希（Base64URL(SHA-256(明文))）</summary>
        public string TokenHash { get; set; } = string.Empty;

        /// <summary>令牌家族Id（轮换链共享，重放检测时整链吊销）</summary>
        public string FamilyId { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>主体Id</summary>
        public string SubjectId { get; set; } = string.Empty;

        /// <summary>客户端Id</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>授权的作用域</summary>
        public List<string> Scopes { get; set; } = new List<string>();

        /// <summary>SSO 会话Id</summary>
        public string? SessionId { get; set; }

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>过期时间</summary>
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>消费时间（轮换后置位；再次使用即视为重放）</summary>
        public DateTimeOffset? ConsumedAt { get; set; }

        /// <summary>吊销时间</summary>
        public DateTimeOffset? RevokedAt { get; set; }

        /// <summary>是否仍可使用</summary>
        public bool IsActive(DateTimeOffset now) =>
            RevokedAt == null && ConsumedAt == null && ExpiresAt > now;
    }

    /// <summary>
    /// 授权码记录（OAuth 2.0 授权码模式）。存储的是授权码哈希，一次性使用。
    /// </summary>
    public class AuthorizationCodeRecord
    {
        /// <summary>授权码哈希（Base64URL(SHA-256(明文))）</summary>
        public string CodeHash { get; set; } = string.Empty;

        /// <summary>客户端Id</summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>主体Id</summary>
        public string SubjectId { get; set; } = string.Empty;

        /// <summary>请求时的回调地址（兑换时必须一致，RFC 6749 §4.1.3）</summary>
        public string RedirectUri { get; set; } = string.Empty;

        /// <summary>授权的作用域</summary>
        public List<string> Scopes { get; set; } = new List<string>();

        /// <summary>PKCE 质询值（RFC 7636）</summary>
        public string? CodeChallenge { get; set; }

        /// <summary>PKCE 质询方法（S256 / plain）</summary>
        public string? CodeChallengeMethod { get; set; }

        /// <summary>OIDC nonce</summary>
        public string? Nonce { get; set; }

        /// <summary>SSO 会话Id</summary>
        public string? SessionId { get; set; }

        /// <summary>创建时间</summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>过期时间</summary>
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>消费时间（一次性；重复兑换将失败）</summary>
        public DateTimeOffset? ConsumedAt { get; set; }
    }
}
