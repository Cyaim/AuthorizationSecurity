using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// OIDC 发现文档（/.well-known/openid-configuration）。
    /// 端点可能为绝对 URL 或相对 Authority 的路径，使用时经客户端统一解析。
    /// </summary>
    public class DiscoveryDocument
    {
        /// <summary>签发者</summary>
        [JsonPropertyName("issuer")]
        public string? Issuer { get; set; }

        /// <summary>令牌端点</summary>
        [JsonPropertyName("token_endpoint")]
        public string? TokenEndpoint { get; set; }

        /// <summary>授权端点</summary>
        [JsonPropertyName("authorization_endpoint")]
        public string? AuthorizationEndpoint { get; set; }

        /// <summary>用户信息端点</summary>
        [JsonPropertyName("userinfo_endpoint")]
        public string? UserInfoEndpoint { get; set; }

        /// <summary>令牌吊销端点 (RFC 7009)</summary>
        [JsonPropertyName("revocation_endpoint")]
        public string? RevocationEndpoint { get; set; }

        /// <summary>令牌自省端点 (RFC 7662)</summary>
        [JsonPropertyName("introspection_endpoint")]
        public string? IntrospectionEndpoint { get; set; }

        /// <summary>JWKS 公钥集地址</summary>
        [JsonPropertyName("jwks_uri")]
        public string? JwksUri { get; set; }

        /// <summary>结束会话端点（单点登出）</summary>
        [JsonPropertyName("end_session_endpoint")]
        public string? EndSessionEndpoint { get; set; }
    }
}
