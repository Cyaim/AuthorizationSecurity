using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 令牌自省端点 POST /connect/introspect（RFC 7662）。
    /// 先按访问令牌（JWT）校验，再按刷新令牌哈希查询存储；都不匹配返回 {active:false}。
    /// </summary>
    internal static class IntrospectionEndpoint
    {
        /// <summary>
        /// 处理自省请求。
        /// </summary>
        public static async Task HandleAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;

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

            string token = form?["token"].ToString() ?? string.Empty;
            if (string.IsNullOrEmpty(token))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 token 参数").ConfigureAwait(false);
                return;
            }

            // 1. 按访问令牌校验
            var tokenService = sp.GetRequiredService<ITokenService>();
            AccessTokenValidation validation = await tokenService.ValidateAccessTokenAsync(token, ct).ConfigureAwait(false);
            if (validation.IsValid && validation.Subject != null)
            {
                AuthSubject subject = validation.Subject;
                var payload = new Dictionary<string, object?>
                {
                    ["active"] = true,
                    ["sub"] = subject.Id,
                    ["token_type"] = "Bearer",
                    ["iss"] = tokenService.Issuer,
                };
                if (!string.IsNullOrEmpty(subject.ClientId))
                {
                    payload["client_id"] = subject.ClientId;
                }
                if (subject.Scopes.Count > 0)
                {
                    payload["scope"] = string.Join(" ", subject.Scopes);
                }
                if (validation.ExpiresAt.HasValue)
                {
                    payload["exp"] = validation.ExpiresAt.Value.ToUnixTimeSeconds();
                }
                if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.PreferredUserName, out string? userName))
                {
                    payload["username"] = userName;
                }
                await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK, payload).ConfigureAwait(false);
                return;
            }

            // 2. 按刷新令牌查询存储
            var tokenStore = sp.GetRequiredService<ITokenStore>();
            var clock = sp.GetRequiredService<IAuthClock>();
            RefreshTokenRecord? record = await tokenStore.FindRefreshTokenAsync(TokenHasher.HashToken(token), ct).ConfigureAwait(false);
            if (record != null && record.IsActive(clock.UtcNow))
            {
                var payload = new Dictionary<string, object?>
                {
                    ["active"] = true,
                    ["sub"] = record.SubjectId,
                    ["client_id"] = record.ClientId,
                    ["exp"] = record.ExpiresAt.ToUnixTimeSeconds(),
                };
                if (record.Scopes.Count > 0)
                {
                    payload["scope"] = string.Join(" ", record.Scopes);
                }
                await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK, payload).ConfigureAwait(false);
                return;
            }

            // 3. 无效令牌：active=false（RFC 7662 §2.2，仍返回 200）
            await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK,
                new Dictionary<string, object?> { ["active"] = false }).ConfigureAwait(false);
        }
    }
}
