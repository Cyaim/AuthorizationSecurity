using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Server.Sso;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 授权端点 GET /connect/authorize（RFC 6749 §4.1 + PKCE RFC 7636）。
    /// 校验客户端与回调地址后：无 SSO 会话跳登录页，有会话签发一次性授权码并回调。
    /// </summary>
    internal static class AuthorizeEndpoint
    {
        private const string LoggerCategory = "Cyaim.Authentication.Server.AuthorizeEndpoint";

        /// <summary>
        /// 处理授权请求。
        /// </summary>
        public static async Task HandleAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            var serverOptions = sp.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(LoggerCategory);
            IQueryCollection query = context.Request.Query;

            // ---- 客户端与回调地址校验：失败时不得重定向，直接 400 文本 ----
            string clientId = query["client_id"].ToString();
            if (string.IsNullOrEmpty(clientId))
            {
                await ServerHttp.WriteTextAsync(context, StatusCodes.Status400BadRequest, "缺少 client_id 参数").ConfigureAwait(false);
                return;
            }

            var clients = sp.GetRequiredService<IClientStore>();
            ClientApplication? client = await clients.FindByClientIdAsync(clientId, ct).ConfigureAwait(false);
            if (client == null || !client.Enabled ||
                !client.AllowedGrantTypes.Contains(AuthConstants.GrantTypes.AuthorizationCode, StringComparer.Ordinal))
            {
                logger.LogWarning(ServerLogEvents.AuthorizeRejected, "授权请求被拒绝：client={ClientId} 无效", clientId);
                await ServerHttp.WriteTextAsync(context, StatusCodes.Status400BadRequest,
                    "client_id 无效、已禁用或未被允许使用授权码模式").ConfigureAwait(false);
                return;
            }

            string redirectUri = query["redirect_uri"].ToString();
            if (string.IsNullOrEmpty(redirectUri) ||
                !client.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
            {
                logger.LogWarning(ServerLogEvents.AuthorizeRejected,
                    "授权请求被拒绝：client={ClientId} redirect_uri 未注册", clientId);
                await ServerHttp.WriteTextAsync(context, StatusCodes.Status400BadRequest,
                    "redirect_uri 缺失或未在客户端注册").ConfigureAwait(false);
                return;
            }

            // ---- 从这里开始错误通过重定向回传（RFC 6749 §4.1.2.1）----
            string state = query["state"].ToString();

            if (!serverOptions.EnableAuthorizationCode)
            {
                RedirectError(context, redirectUri, "unauthorized_client", "授权码模式未启用", state);
                return;
            }

            string responseType = query["response_type"].ToString();
            if (!string.Equals(responseType, "code", StringComparison.Ordinal))
            {
                RedirectError(context, redirectUri, "unsupported_response_type", "仅支持 response_type=code", state);
                return;
            }

            List<string> scopes = ServerHttp.SplitScopes(query["scope"]);
            if (!ServerHttp.ScopesAllowed(scopes, client.AllowedScopes))
            {
                RedirectError(context, redirectUri, "invalid_scope", "请求的作用域超出客户端允许范围", state);
                return;
            }

            string codeChallenge = query["code_challenge"].ToString();
            string codeChallengeMethod = query["code_challenge_method"].ToString();
            if (client.RequirePkce && string.IsNullOrEmpty(codeChallenge))
            {
                RedirectError(context, redirectUri, "invalid_request", "该客户端要求 PKCE（缺少 code_challenge）", state);
                return;
            }
            if (!string.IsNullOrEmpty(codeChallenge) &&
                !string.Equals(codeChallengeMethod, "S256", StringComparison.Ordinal))
            {
                RedirectError(context, redirectUri, "invalid_request", "code_challenge_method 仅支持 S256", state);
                return;
            }

            // ---- SSO 会话检查：未登录跳转登录页 ----
            var sso = sp.GetRequiredService<SsoSessionService>();
            SsoSession? session = sso.Validate(context);
            if (session == null)
            {
                string returnUrl = context.Request.GetEncodedUrl();
                string loginUrl = QueryHelpers.AddQueryString(serverOptions.LoginPath, "returnUrl", returnUrl);
                context.Response.Redirect(loginUrl);
                return;
            }

            // ---- 签发一次性授权码 ----
            var tokenStore = sp.GetRequiredService<ITokenStore>();
            var clock = sp.GetRequiredService<IAuthClock>();
            DateTimeOffset now = clock.UtcNow;
            string code = TokenHasher.CreateToken();
            string nonce = query["nonce"].ToString();

            var record = new AuthorizationCodeRecord
            {
                CodeHash = TokenHasher.HashToken(code),
                ClientId = client.ClientId,
                SubjectId = session.SubjectId,
                RedirectUri = redirectUri,
                Scopes = scopes,
                CodeChallenge = string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
                CodeChallengeMethod = string.IsNullOrEmpty(codeChallenge) ? null : "S256",
                Nonce = string.IsNullOrEmpty(nonce) ? null : nonce,
                SessionId = session.Sid,
                CreatedAt = now,
                ExpiresAt = now + TimeSpan.FromSeconds(client.AuthorizationCodeLifetimeSeconds),
            };
            await tokenStore.SaveAuthorizationCodeAsync(record, ct).ConfigureAwait(false);

            logger.LogInformation(ServerLogEvents.AuthorizationCodeIssued,
                "授权码签发 client={ClientId} sub={SubjectId} sid={SessionId}",
                client.ClientId, session.SubjectId, session.Sid);

            string callback = QueryHelpers.AddQueryString(redirectUri, "code", code);
            if (!string.IsNullOrEmpty(state))
            {
                callback = QueryHelpers.AddQueryString(callback, "state", state);
            }
            context.Response.Redirect(callback);
        }

        /// <summary>
        /// 通过 302 回调携带 error 与 error_description（state 有则原样回传）。
        /// </summary>
        private static void RedirectError(HttpContext context, string redirectUri, string error, string description, string state)
        {
            string url = QueryHelpers.AddQueryString(redirectUri, "error", error);
            url = QueryHelpers.AddQueryString(url, "error_description", description);
            if (!string.IsNullOrEmpty(state))
            {
                url = QueryHelpers.AddQueryString(url, "state", state);
            }
            context.Response.Redirect(url);
        }
    }
}
