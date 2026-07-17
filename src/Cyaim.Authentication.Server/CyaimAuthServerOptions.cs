using System;
using Cyaim.Authentication.Abstractions;
using Microsoft.AspNetCore.Http;

namespace Cyaim.Authentication.Server
{
    /// <summary>
    /// 独立授权服务器配置（对标 IdentityServer 核心端点）。
    /// </summary>
    public class CyaimAuthServerOptions
    {
        /// <summary>
        /// 对外公开的基地址（发现文档中各端点 URL 的前缀，例如 https://auth.example.com）。
        /// 为空时按当前请求的 scheme://host 生成。
        /// </summary>
        public string? PublicOrigin { get; set; }

        /// <summary>是否启用 password 授权（RFC 6749 §4.3），默认 true</summary>
        public bool EnablePasswordGrant { get; set; } = true;

        /// <summary>是否启用 client_credentials 授权（RFC 6749 §4.4），默认 true</summary>
        public bool EnableClientCredentials { get; set; } = true;

        /// <summary>是否启用 authorization_code 授权（RFC 6749 §4.1 + PKCE RFC 7636），默认 true</summary>
        public bool EnableAuthorizationCode { get; set; } = true;

        /// <summary>是否启用刷新令牌（RFC 6749 §6），默认 true</summary>
        public bool EnableRefreshTokens { get; set; } = true;

        /// <summary>SSO 会话 Cookie 名称，默认 cyaim_sso</summary>
        public string SsoCookieName { get; set; } = "cyaim_sso";

        /// <summary>SSO 会话有效期，默认 8 小时</summary>
        public TimeSpan SsoSessionLifetime { get; set; } = TimeSpan.FromHours(8);

        /// <summary>登录页路径，默认 <see cref="AuthConstants.Endpoints.Login"/></summary>
        public string LoginPath { get; set; } = AuthConstants.Endpoints.Login;

        /// <summary>服务器名称（登录页标题等展示用），默认 "Cyaim Auth"</summary>
        public string ServerName { get; set; } = "Cyaim Auth";

        /// <summary>
        /// SSO Cookie 的 Secure 策略。默认 <see cref="CookieSecurePolicy.SameAsRequest"/>（HTTPS 请求才置 Secure）；
        /// 反向代理终止 TLS（后端收到 HTTP）时应设为 <see cref="CookieSecurePolicy.Always"/>，
        /// 以免会话 Cookie 以明文下发。生产建议 Always（并确保对外为 HTTPS）。
        /// </summary>
        public CookieSecurePolicy SsoCookieSecurePolicy { get; set; } = CookieSecurePolicy.SameAsRequest;
    }
}
