using System.Text.Json.Serialization;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// OIDC UserInfo 端点响应。role/permissions 兼容单值字符串与数组两种 JSON 形态。
    /// </summary>
    public class UserInfoResponse
    {
        /// <summary>主体标识</summary>
        [JsonPropertyName("sub")]
        public string? Sub { get; set; }

        /// <summary>显示名</summary>
        [JsonPropertyName("name")]
        public string? Name { get; set; }

        /// <summary>首选用户名</summary>
        [JsonPropertyName("preferred_username")]
        public string? PreferredUsername { get; set; }

        /// <summary>邮箱</summary>
        [JsonPropertyName("email")]
        public string? Email { get; set; }

        /// <summary>角色</summary>
        [JsonPropertyName("role")]
        [JsonConverter(typeof(StringOrArrayJsonConverter))]
        public string[]? Role { get; set; }

        /// <summary>权限代码</summary>
        [JsonPropertyName("permissions")]
        [JsonConverter(typeof(StringOrArrayJsonConverter))]
        public string[]? Permissions { get; set; }

        /// <summary>作用域（空格分隔）</summary>
        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }
}
