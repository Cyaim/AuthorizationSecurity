using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Server.Sso;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 账户端点：登录页（GET/POST /account/login）与登出（/account/logout、/connect/endsession）。
    /// </summary>
    internal static class AccountEndpoints
    {
        private const string LoggerCategory = "Cyaim.Authentication.Server.AccountEndpoints";

        /// <summary>
        /// GET /account/login：返回内嵌登录页。
        /// </summary>
        public static async Task HandleLoginPageAsync(HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;
            string returnUrl = context.Request.Query["returnUrl"].ToString();
            bool showError = string.Equals(context.Request.Query["err"].ToString(), "1", StringComparison.Ordinal);

            string html = LoginPage.Render(options.ServerName, options.LoginPath, returnUrl, showError);
            await ServerHttp.WriteHtmlAsync(context, StatusCodes.Status200OK, html).ConfigureAwait(false);
        }

        /// <summary>
        /// POST /account/login：校验凭据，成功签发 SSO 会话 Cookie 并跳转 returnUrl。
        /// </summary>
        public static async Task HandleLoginSubmitAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            var options = sp.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;

            if (!context.Request.HasFormContentType)
            {
                await ServerHttp.WriteTextAsync(context, StatusCodes.Status400BadRequest, "请求必须为表单").ConfigureAwait(false);
                return;
            }

            // 登录 CSRF 防护：登录 POST 不依赖既有 Cookie（SameSite 无保护），校验 Origin/Referer
            // 属于本站，拒绝跨站自动提交（防会话强制登入攻击）。
            if (!ServerHttp.IsSameOriginRequest(context))
            {
                await ServerHttp.WriteTextAsync(context, StatusCodes.Status400BadRequest, "跨站请求被拒绝").ConfigureAwait(false);
                return;
            }

            IFormCollection form = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);
            string userName = form["username"].ToString();
            string password = form["password"].ToString();
            string returnUrl = form["returnUrl"].ToString();

            var credentials = sp.GetRequiredService<UserCredentialService>();
            string? remoteIp = context.Connection.RemoteIpAddress?.ToString();
            CredentialValidationResult result = await credentials.ValidateAsync(userName, password, remoteIp, ct).ConfigureAwait(false);

            if (!result.Success)
            {
                // 回登录页并提示错误（审计已由 UserCredentialService 记录）
                var failQuery = new Dictionary<string, string?> { ["err"] = "1" };
                if (!string.IsNullOrEmpty(returnUrl))
                {
                    failQuery["returnUrl"] = returnUrl;
                }
                context.Response.Redirect(QueryHelpers.AddQueryString(options.LoginPath, failQuery));
                return;
            }

            var sso = sp.GetRequiredService<SsoSessionService>();
            sso.Issue(context, result.User!);

            // 防开放重定向：仅允许本站相对路径或同 origin 地址
            string target = ServerHttp.IsSafeReturnUrl(context, returnUrl) ? returnUrl : "/";
            context.Response.Redirect(target);
        }

        /// <summary>
        /// GET|POST /account/logout 与 GET /connect/endsession：
        /// 清除 SSO Cookie；post_logout_redirect_uri 匹配任一客户端注册地址则跳转，否则返回已登出页。
        /// </summary>
        public static async Task HandleLogoutAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            var options = sp.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(LoggerCategory);

            var sso = sp.GetRequiredService<SsoSessionService>();
            SsoSession? session = sso.Validate(context);
            sso.Clear(context);

            // 审计登出
            var audit = sp.GetRequiredService<IAuditLogger>();
            var clock = sp.GetRequiredService<IAuthClock>();
            await audit.WriteAsync(new AuditEvent
            {
                Category = AuditCategory.Logout,
                Outcome = AuditOutcome.Success,
                SubjectId = session?.SubjectId,
                SubjectName = session?.Name,
                Action = "logout",
                Detail = session != null ? $"sid={session.Sid}" : "无有效会话",
                RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
                Timestamp = clock.UtcNow,
            }, ct).ConfigureAwait(false);

            logger.LogInformation(ServerLogEvents.SsoSessionCleared,
                "登出 sub={SubjectId} sid={SessionId}", session?.SubjectId, session?.Sid);

            // post_logout_redirect_uri 白名单校验（任一客户端的注册地址精确匹配）
            string postLogoutRedirectUri = context.Request.Query["post_logout_redirect_uri"].ToString();
            if (string.IsNullOrEmpty(postLogoutRedirectUri) && context.Request.HasFormContentType)
            {
                IFormCollection form = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);
                postLogoutRedirectUri = form["post_logout_redirect_uri"].ToString();
            }

            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                var clients = sp.GetRequiredService<IClientStore>();
                IReadOnlyList<ClientApplication> all = await clients.GetAllAsync(ct).ConfigureAwait(false);
                bool allowed = all.Any(c =>
                    c.Enabled && c.PostLogoutRedirectUris.Contains(postLogoutRedirectUri, StringComparer.Ordinal));
                if (allowed)
                {
                    context.Response.Redirect(postLogoutRedirectUri);
                    return;
                }
            }

            await ServerHttp.WriteHtmlAsync(context, StatusCodes.Status200OK,
                LoginPage.RenderLoggedOut(options.ServerName)).ConfigureAwait(false);
        }
    }
}
