using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// OAuth 2.0 令牌端点错误响应 (RFC 6749 §5.2)。
    /// </summary>
    public class TokenErrorResponse
    {
        /// <summary>错误代码（如 invalid_grant、invalid_client）</summary>
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        /// <summary>人类可读错误描述</summary>
        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }
}
