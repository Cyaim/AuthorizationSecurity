using System;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Core;
using Microsoft.AspNetCore.Http;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// ASP.NET Core 集成配置（继承核心引擎配置，一处配置全部生效）。
    /// </summary>
    public class CyaimAuthOptions : CyaimAuthCoreOptions
    {
        /// <summary>凭据请求头名称，默认 Authorization（Bearer 方案，RFC 6750 §2.1）</summary>
        public string AuthorizationHeaderName { get; set; } = "Authorization";

        /// <summary>允许从查询字符串提取令牌（WebSocket 握手常用，RFC 6750 §2.3），默认 true</summary>
        public bool AllowTokenFromQuery { get; set; } = true;

        /// <summary>查询字符串令牌参数名，默认 access_token</summary>
        public string QueryTokenParameter { get; set; } = "access_token";

        /// <summary>允许从 Cookie 提取令牌，默认 false</summary>
        public bool AllowTokenFromCookie { get; set; }

        /// <summary>Cookie 令牌名称，默认 cyaim_token</summary>
        public string CookieTokenName { get; set; } = "cyaim_token";

        /// <summary>
        /// true 时所有端点默认要求已认证（未标注权限的端点也拦截，[AllowGuest]/[AllowAnonymous] 放行）；
        /// false（默认）仅拦截标注了 [RequirePermission] 的端点。
        /// </summary>
        public bool ProtectAllEndpoints { get; set; }

        /// <summary>拒绝请求写入审计日志，默认 true</summary>
        public bool AuditDenials { get; set; } = true;

        /// <summary>启动时扫描端点权限并登记到权限定义存储，默认 true</summary>
        public bool ScanEndpointPermissions { get; set; } = true;

        /// <summary>
        /// 自定义拒绝响应（设置后替代默认 JSON 响应）。
        /// </summary>
        public Func<HttpContext, AuthorizationDecision?, Task>? OnDenied { get; set; }
    }
}
