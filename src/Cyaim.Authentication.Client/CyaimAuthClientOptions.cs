using System;
using System.Collections.Generic;
using Cyaim.Authentication.Abstractions;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 客户端 SDK 配置。
    /// </summary>
    public class CyaimAuthClientOptions
    {
        /// <summary>
        /// 授权服务器地址（必填），例如 https://auth.example.com。
        /// </summary>
        public string Authority { get; set; } = string.Empty;

        /// <summary>
        /// 客户端标识。
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        /// <summary>
        /// 客户端密钥（机密客户端使用；公共客户端如 WASM/桌面应用可为 null）。
        /// </summary>
        public string? ClientSecret { get; set; }

        /// <summary>
        /// 请求的作用域。默认 ["permissions", "offline_access"]（携带权限声明 + 签发刷新令牌）。
        /// </summary>
        public List<string> Scopes { get; set; } = new List<string>
        {
            AuthConstants.Scopes.Permissions,
            AuthConstants.Scopes.OfflineAccess,
        };

        /// <summary>
        /// 访问令牌过期时是否自动用刷新令牌续期。默认 true。
        /// </summary>
        public bool AutoRefresh { get; set; } = true;

        /// <summary>
        /// 提前刷新窗口：令牌剩余有效期小于该值即视为过期需要刷新。默认 60 秒。
        /// </summary>
        public TimeSpan RefreshSkew { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// 发现文档路径（相对 <see cref="Authority"/>）。默认 "/.well-known/openid-configuration"。
        /// </summary>
        public string DiscoveryPath { get; set; } = AuthConstants.Endpoints.Discovery;
    }
}
