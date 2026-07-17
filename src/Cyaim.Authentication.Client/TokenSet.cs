using System;
using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 本地持有的一组令牌（访问令牌 + 可选刷新令牌）。
    /// </summary>
    public class TokenSet
    {
        /// <summary>访问令牌</summary>
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>刷新令牌（无 offline_access 时为 null）</summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>访问令牌过期时刻（UTC）</summary>
        [JsonPropertyName("expires_at")]
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>授予的作用域</summary>
        [JsonPropertyName("scopes")]
        public string[]? Scopes { get; set; }
    }
}
