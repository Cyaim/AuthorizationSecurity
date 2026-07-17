using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// OAuth 2.0 令牌端点成功响应 (RFC 6749 §5.1)。
    /// </summary>
    public class TokenResponse
    {
        /// <summary>访问令牌</summary>
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        /// <summary>令牌类型（通常为 "Bearer"）</summary>
        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        /// <summary>有效期（秒）</summary>
        [JsonPropertyName("expires_in")]
        public long ExpiresIn { get; set; }

        /// <summary>刷新令牌（申请了 offline_access 时返回）</summary>
        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        /// <summary>实际授予的作用域（空格分隔）</summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }
}
