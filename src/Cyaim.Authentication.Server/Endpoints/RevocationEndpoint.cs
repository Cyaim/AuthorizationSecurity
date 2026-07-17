using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 令牌吊销端点 POST /connect/revocation（RFC 7009）。
    /// 刷新令牌吊销整个家族（仅限持有该令牌的客户端）；访问令牌无状态，直接返回 200。
    /// </summary>
    internal static class RevocationEndpoint
    {
        private const string LoggerCategory = "Cyaim.Authentication.Server.RevocationEndpoint";

        /// <summary>
        /// 处理吊销请求。
        /// </summary>
        public static async Task HandleAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(LoggerCategory);

            IFormCollection? form = context.Request.HasFormContentType
                ? await context.Request.ReadFormAsync(ct).ConfigureAwait(false)
                : null;

            // 客户端认证（与令牌端点相同）
            ClientAuthResult auth = await ClientAuthenticator.AuthenticateAsync(context, form, ct).ConfigureAwait(false);
            if (!auth.Success)
            {
                await ClientAuthenticator.WriteFailureAsync(context, auth).ConfigureAwait(false);
                return;
            }
            ClientApplication client = auth.Client!;

            string token = form?["token"].ToString() ?? string.Empty;
            if (string.IsNullOrEmpty(token))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 token 参数").ConfigureAwait(false);
                return;
            }

            // 尝试按刷新令牌吊销（token_type_hint 仅作提示；访问令牌无状态无需处理）
            var tokenStore = sp.GetRequiredService<ITokenStore>();
            RefreshTokenRecord? record = await tokenStore.FindRefreshTokenAsync(TokenHasher.HashToken(token), ct).ConfigureAwait(false);
            if (record != null && string.Equals(record.ClientId, client.ClientId, StringComparison.Ordinal))
            {
                await tokenStore.RevokeRefreshTokenFamilyAsync(record.FamilyId, ct).ConfigureAwait(false);

                var audit = sp.GetRequiredService<IAuditLogger>();
                var clock = sp.GetRequiredService<IAuthClock>();
                await audit.WriteAsync(new AuditEvent
                {
                    Category = AuditCategory.TokenRevoked,
                    Outcome = AuditOutcome.Success,
                    SubjectId = record.SubjectId,
                    ClientId = client.ClientId,
                    Action = "revoke_refresh_token",
                    Detail = $"family={record.FamilyId}",
                    RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
                    Timestamp = clock.UtcNow,
                }, ct).ConfigureAwait(false);

                logger.LogInformation(ServerLogEvents.TokenRevoked,
                    "刷新令牌家族已吊销 client={ClientId} sub={SubjectId} family={FamilyId}",
                    client.ClientId, record.SubjectId, record.FamilyId);
            }

            // RFC 7009 §2.2：无论令牌是否存在均返回 200
            context.Response.StatusCode = StatusCodes.Status200OK;
        }
    }
}
