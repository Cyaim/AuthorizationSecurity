using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Core.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 令牌端点 POST /connect/token（RFC 6749 §3.2）。
    /// 支持 client_credentials / password / refresh_token / authorization_code(+PKCE) 授权。
    /// </summary>
    internal static class TokenEndpoint
    {
        private const string LoggerCategory = "Cyaim.Authentication.Server.TokenEndpoint";

        /// <summary>
        /// 处理令牌请求。
        /// </summary>
        public static async Task HandleAsync(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            var serverOptions = sp.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(LoggerCategory);

            if (!context.Request.HasFormContentType)
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "请求必须为 application/x-www-form-urlencoded 表单").ConfigureAwait(false);
                return;
            }

            IFormCollection form = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);

            // 客户端认证（Basic 头或表单）
            ClientAuthResult auth = await ClientAuthenticator.AuthenticateAsync(context, form, ct).ConfigureAwait(false);
            if (!auth.Success)
            {
                await ClientAuthenticator.WriteFailureAsync(context, auth).ConfigureAwait(false);
                return;
            }
            ClientApplication client = auth.Client!;

            string grantType = form["grant_type"].ToString();
            if (string.IsNullOrEmpty(grantType))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 grant_type 参数").ConfigureAwait(false);
                return;
            }

            if (!IsGrantEnabled(serverOptions, grantType))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "unsupported_grant_type", $"授权类型 {grantType} 未启用或不受支持").ConfigureAwait(false);
                return;
            }

            if (!client.AllowedGrantTypes.Contains(grantType, StringComparer.Ordinal))
            {
                logger.LogWarning(ServerLogEvents.TokenRejected,
                    "客户端 {ClientId} 未被允许使用授权类型 {GrantType}", client.ClientId, grantType);
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "unauthorized_client", "客户端未被允许使用该授权类型").ConfigureAwait(false);
                return;
            }

            switch (grantType)
            {
                case AuthConstants.GrantTypes.ClientCredentials:
                    await HandleClientCredentialsAsync(context, client, form, logger, ct).ConfigureAwait(false);
                    break;
                case AuthConstants.GrantTypes.Password:
                    await HandlePasswordAsync(context, client, form, serverOptions, logger, ct).ConfigureAwait(false);
                    break;
                case AuthConstants.GrantTypes.RefreshToken:
                    await HandleRefreshTokenAsync(context, client, form, logger, ct).ConfigureAwait(false);
                    break;
                case AuthConstants.GrantTypes.AuthorizationCode:
                    await HandleAuthorizationCodeAsync(context, client, form, serverOptions, logger, ct).ConfigureAwait(false);
                    break;
                default:
                    await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                        "unsupported_grant_type", $"授权类型 {grantType} 不受支持").ConfigureAwait(false);
                    break;
            }
        }

        /// <summary>
        /// client_credentials 授权（RFC 6749 §4.4）。
        /// </summary>
        private static async Task HandleClientCredentialsAsync(
            HttpContext context, ClientApplication client, IFormCollection form, ILogger logger, CancellationToken ct)
        {
            List<string> scopes = ServerHttp.SplitScopes(form["scope"]);
            if (!ServerHttp.ScopesAllowed(scopes, client.AllowedScopes))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_scope", "请求的作用域超出客户端允许范围").ConfigureAwait(false);
                return;
            }

            AuthSubject subject = SubjectBuilder.FromClient(client, scopes);
            var coreOptions = context.RequestServices.GetRequiredService<IOptions<CyaimAuthCoreOptions>>().Value;
            IReadOnlyList<string>? permissionCodes = coreOptions.IncludePermissionsInToken ? client.Permissions : null;

            await IssueAndRespondAsync(context, client, subject, scopes,
                AuthConstants.GrantTypes.ClientCredentials, null, permissionCodes, logger, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// password 授权（RFC 6749 §4.3）。
        /// </summary>
        private static async Task HandlePasswordAsync(
            HttpContext context, ClientApplication client, IFormCollection form,
            CyaimAuthServerOptions serverOptions, ILogger logger, CancellationToken ct)
        {
            string userName = form["username"].ToString();
            string password = form["password"].ToString();
            if (string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(password))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 username 或 password 参数").ConfigureAwait(false);
                return;
            }

            List<string> scopes = ServerHttp.SplitScopes(form["scope"]);
            if (!ServerHttp.ScopesAllowed(scopes, client.AllowedScopes))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_scope", "请求的作用域超出客户端允许范围").ConfigureAwait(false);
                return;
            }

            var credentials = context.RequestServices.GetRequiredService<UserCredentialService>();
            string? remoteIp = context.Connection.RemoteIpAddress?.ToString();
            CredentialValidationResult result = await credentials.ValidateAsync(userName, password, remoteIp, ct).ConfigureAwait(false);
            if (!result.Success)
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "用户凭据无效").ConfigureAwait(false);
                return;
            }

            AuthSubject subject = SubjectBuilder.FromUser(result.User!, client.ClientId, scopes, null);
            IReadOnlyList<string>? permissionCodes = await ResolveUserPermissionsAsync(context, subject, ct).ConfigureAwait(false);

            string? refreshToken = null;
            if (ShouldIssueRefreshToken(serverOptions, client, scopes))
            {
                var refreshManager = context.RequestServices.GetRequiredService<RefreshTokenManager>();
                (refreshToken, _) = await refreshManager.IssueAsync(
                    subject.Id, client.ClientId, scopes, null,
                    TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds), ct).ConfigureAwait(false);
            }

            await IssueAndRespondAsync(context, client, subject, scopes,
                AuthConstants.GrantTypes.Password, refreshToken, permissionCodes, logger, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// refresh_token 授权（RFC 6749 §6）：轮换刷新令牌并按最新用户数据重建主体。
        /// </summary>
        private static async Task HandleRefreshTokenAsync(
            HttpContext context, ClientApplication client, IFormCollection form, ILogger logger, CancellationToken ct)
        {
            string refreshToken = form["refresh_token"].ToString();
            if (string.IsNullOrEmpty(refreshToken))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 refresh_token 参数").ConfigureAwait(false);
                return;
            }

            var refreshManager = context.RequestServices.GetRequiredService<RefreshTokenManager>();
            RefreshExchangeResult exchange = await refreshManager.ExchangeAsync(refreshToken, client.ClientId, ct).ConfigureAwait(false);
            if (!exchange.Success)
            {
                if (exchange.ReplayDetected)
                {
                    logger.LogWarning(ServerLogEvents.TokenRejected,
                        "刷新令牌重放已拦截 client={ClientId}", client.ClientId);
                }
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    exchange.Error ?? "invalid_grant", exchange.ErrorDescription).ConfigureAwait(false);
                return;
            }

            RefreshTokenRecord record = exchange.Record!;

            // 按存储中的最新数据重建主体（拿最新角色/权限）
            var users = context.RequestServices.GetRequiredService<IUserStore>();
            AuthUser? user = await users.FindByIdAsync(record.SubjectId, ct).ConfigureAwait(false);
            if (user == null || !user.IsEnabled)
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "用户不存在或已禁用").ConfigureAwait(false);
                return;
            }

            AuthSubject subject = SubjectBuilder.FromUser(user, client.ClientId, record.Scopes, record.SessionId);
            IReadOnlyList<string>? permissionCodes = await ResolveUserPermissionsAsync(context, subject, ct).ConfigureAwait(false);

            await IssueAndRespondAsync(context, client, subject, record.Scopes,
                AuthConstants.GrantTypes.RefreshToken, exchange.NewToken, permissionCodes, logger, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// authorization_code 授权（RFC 6749 §4.1 + PKCE RFC 7636）。
        /// </summary>
        private static async Task HandleAuthorizationCodeAsync(
            HttpContext context, ClientApplication client, IFormCollection form,
            CyaimAuthServerOptions serverOptions, ILogger logger, CancellationToken ct)
        {
            string code = form["code"].ToString();
            string redirectUri = form["redirect_uri"].ToString();
            if (string.IsNullOrEmpty(code))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_request", "缺少 code 参数").ConfigureAwait(false);
                return;
            }

            var tokenStore = context.RequestServices.GetRequiredService<ITokenStore>();
            AuthorizationCodeRecord? record = await tokenStore.ConsumeAuthorizationCodeAsync(
                TokenHasher.HashToken(code), ct).ConfigureAwait(false);
            if (record == null)
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "授权码无效、已过期或已使用").ConfigureAwait(false);
                return;
            }

            if (!string.Equals(record.ClientId, client.ClientId, StringComparison.Ordinal))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "授权码不属于该客户端").ConfigureAwait(false);
                return;
            }

            // redirect_uri 必须与授权请求时精确一致（RFC 6749 §4.1.3）
            if (string.IsNullOrEmpty(redirectUri) ||
                !string.Equals(record.RedirectUri, redirectUri, StringComparison.Ordinal))
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "redirect_uri 与授权请求不一致").ConfigureAwait(false);
                return;
            }

            // PKCE 校验（仅支持 S256）
            if (!string.IsNullOrEmpty(record.CodeChallenge))
            {
                string verifier = form["code_verifier"].ToString();
                if (string.IsNullOrEmpty(verifier))
                {
                    await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                        "invalid_grant", "缺少 code_verifier 参数").ConfigureAwait(false);
                    return;
                }
                if (!string.Equals(record.CodeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase) ||
                    !VerifyPkce(record.CodeChallenge!, verifier))
                {
                    await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                        "invalid_grant", "PKCE 校验失败").ConfigureAwait(false);
                    return;
                }
            }

            var users = context.RequestServices.GetRequiredService<IUserStore>();
            AuthUser? user = await users.FindByIdAsync(record.SubjectId, ct).ConfigureAwait(false);
            if (user == null || !user.IsEnabled)
            {
                await ServerHttp.WriteOAuthErrorAsync(context, StatusCodes.Status400BadRequest,
                    "invalid_grant", "用户不存在或已禁用").ConfigureAwait(false);
                return;
            }

            AuthSubject subject = SubjectBuilder.FromUser(user, client.ClientId, record.Scopes, record.SessionId);
            IReadOnlyList<string>? permissionCodes = await ResolveUserPermissionsAsync(context, subject, ct).ConfigureAwait(false);

            string? refreshToken = null;
            if (ShouldIssueRefreshToken(serverOptions, client, record.Scopes))
            {
                var refreshManager = context.RequestServices.GetRequiredService<RefreshTokenManager>();
                (refreshToken, _) = await refreshManager.IssueAsync(
                    subject.Id, client.ClientId, record.Scopes, record.SessionId,
                    TimeSpan.FromSeconds(client.RefreshTokenLifetimeSeconds), ct).ConfigureAwait(false);
            }

            await IssueAndRespondAsync(context, client, subject, record.Scopes,
                AuthConstants.GrantTypes.AuthorizationCode, refreshToken, permissionCodes, logger, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// 签发访问令牌、写审计并输出成功响应（带 no-store 缓存头）。
        /// </summary>
        private static async Task IssueAndRespondAsync(
            HttpContext context, ClientApplication client, AuthSubject subject,
            IReadOnlyList<string> scopes, string grantType, string? refreshToken,
            IReadOnlyList<string>? permissionCodes, ILogger logger, CancellationToken ct)
        {
            IServiceProvider sp = context.RequestServices;
            var tokenService = sp.GetRequiredService<ITokenService>();
            var coreOptions = sp.GetRequiredService<IOptions<CyaimAuthCoreOptions>>().Value;

            IssuedToken token = await tokenService.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = subject,
                Client = client,
                Scopes = scopes,
                IncludePermissionClaims = coreOptions.IncludePermissionsInToken && permissionCodes != null,
                PermissionCodes = permissionCodes,
            }, ct).ConfigureAwait(false);

            // 审计：每次签发都记录，Detail 含 grant_type
            var audit = sp.GetRequiredService<IAuditLogger>();
            var clock = sp.GetRequiredService<IAuthClock>();
            await audit.WriteAsync(new AuditEvent
            {
                Category = AuditCategory.TokenIssued,
                Outcome = AuditOutcome.Success,
                SubjectId = subject.Id,
                SubjectName = subject.Name,
                ClientId = client.ClientId,
                Action = "token_issued",
                Detail = $"grant_type={grantType}; scope={string.Join(" ", scopes)}; refresh_token={(refreshToken != null ? "yes" : "no")}",
                RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
                Timestamp = clock.UtcNow,
            }, ct).ConfigureAwait(false);

            logger.LogInformation(ServerLogEvents.TokenGranted,
                "令牌签发 grant={GrantType} sub={SubjectId} client={ClientId} expiresIn={ExpiresIn}s",
                grantType, subject.Id, client.ClientId, token.ExpiresInSeconds);

            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";

            var payload = new Dictionary<string, object?>
            {
                ["access_token"] = token.Token,
                ["token_type"] = "Bearer",
                ["expires_in"] = token.ExpiresInSeconds,
            };
            if (scopes.Count > 0)
            {
                payload["scope"] = string.Join(" ", scopes);
            }
            if (!string.IsNullOrEmpty(refreshToken))
            {
                payload["refresh_token"] = refreshToken;
            }

            await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK, payload).ConfigureAwait(false);
        }

        /// <summary>
        /// 计算用户主体写入令牌的权限代码（IncludePermissionsInToken 时取评估器允许集）。
        /// </summary>
        private static async Task<IReadOnlyList<string>?> ResolveUserPermissionsAsync(
            HttpContext context, AuthSubject subject, CancellationToken ct)
        {
            var coreOptions = context.RequestServices.GetRequiredService<IOptions<CyaimAuthCoreOptions>>().Value;
            if (!coreOptions.IncludePermissionsInToken)
            {
                return null;
            }
            var evaluator = context.RequestServices.GetRequiredService<IPermissionEvaluator>();
            var permissionSet = await evaluator.GetPermissionSetAsync(subject, ct).ConfigureAwait(false);
            return permissionSet.Allows;
        }

        /// <summary>
        /// 判断是否随访问令牌附带刷新令牌（scope 含 offline_access 且客户端允许且服务器启用）。
        /// </summary>
        private static bool ShouldIssueRefreshToken(
            CyaimAuthServerOptions serverOptions, ClientApplication client, IReadOnlyList<string> scopes)
        {
            return serverOptions.EnableRefreshTokens &&
                   client.AllowOfflineAccess &&
                   scopes.Contains(AuthConstants.Scopes.OfflineAccess, StringComparer.Ordinal);
        }

        /// <summary>
        /// PKCE S256 校验：Base64URL(SHA256(code_verifier)) == code_challenge（常量时间比较）。
        /// </summary>
        private static bool VerifyPkce(string codeChallenge, string codeVerifier)
        {
            byte[] computed;
            using (var sha = SHA256.Create())
            {
                computed = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
            }
            byte[] expected;
            try
            {
                expected = Base64Url.Decode(codeChallenge);
            }
            catch (FormatException)
            {
                return false;
            }
            return CryptographicOperations.FixedTimeEquals(computed, expected);
        }

        /// <summary>
        /// 授权类型是否被服务器配置启用。
        /// </summary>
        private static bool IsGrantEnabled(CyaimAuthServerOptions options, string grantType)
        {
            switch (grantType)
            {
                case AuthConstants.GrantTypes.ClientCredentials:
                    return options.EnableClientCredentials;
                case AuthConstants.GrantTypes.Password:
                    return options.EnablePasswordGrant;
                case AuthConstants.GrantTypes.AuthorizationCode:
                    return options.EnableAuthorizationCode;
                case AuthConstants.GrantTypes.RefreshToken:
                    return options.EnableRefreshTokens;
                default:
                    return false;
            }
        }
    }
}
