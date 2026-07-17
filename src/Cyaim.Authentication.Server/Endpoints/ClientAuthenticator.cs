using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 令牌/自省/吊销端点的客户端认证（RFC 6749 §2.3.1）：
    /// 支持 client_secret_basic（Basic 头，值需 URL 解码）与 client_secret_post（表单 client_id/client_secret）。
    /// 机密客户端必须校验密钥；公共客户端（无密钥哈希）仅需 client_id。
    /// </summary>
    internal static class ClientAuthenticator
    {
        /// <summary>
        /// 认证请求携带的客户端凭据。
        /// </summary>
        public static async Task<ClientAuthResult> AuthenticateAsync(HttpContext context, IFormCollection? form, CancellationToken cancellationToken)
        {
            IServiceProvider sp = context.RequestServices;
            IClientStore clients = sp.GetRequiredService<IClientStore>();
            IPasswordHasher hasher = sp.GetRequiredService<IPasswordHasher>();
            ILogger logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Cyaim.Authentication.Server.ClientAuthenticator");

            string? clientId = null;
            string? clientSecret = null;
            bool usedBasic = false;

            // 1. Basic 认证头：Basic base64(urlencode(client_id):urlencode(client_secret))
            string authHeader = context.Request.Headers.Authorization.ToString();
            if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                usedBasic = true;
                if (!TryParseBasic(authHeader.Substring(6).Trim(), out clientId, out clientSecret))
                {
                    return ClientAuthResult.Fail(StatusCodes.Status400BadRequest, "invalid_request", "Basic 认证头格式不正确", usedBasic);
                }
            }

            // 2. 表单参数 client_id / client_secret
            if (string.IsNullOrEmpty(clientId) && form != null)
            {
                clientId = form["client_id"].ToString();
                string formSecret = form["client_secret"].ToString();
                if (!string.IsNullOrEmpty(formSecret))
                {
                    clientSecret = formSecret;
                }
            }

            if (string.IsNullOrEmpty(clientId))
            {
                return ClientAuthResult.Fail(StatusCodes.Status401Unauthorized, "invalid_client", "缺少客户端凭据", usedBasic);
            }

            ClientApplication? client = await clients.FindByClientIdAsync(clientId!, cancellationToken).ConfigureAwait(false);
            if (client == null || !client.Enabled)
            {
                logger.LogWarning(ServerLogEvents.ClientAuthFailed, "客户端认证失败：client={ClientId} 不存在或已禁用", clientId);
                return ClientAuthResult.Fail(StatusCodes.Status401Unauthorized, "invalid_client", "客户端无效", usedBasic);
            }

            if (client.ClientSecretHash != null)
            {
                // 机密客户端必须提供并通过密钥校验
                if (string.IsNullOrEmpty(clientSecret) || !hasher.Verify(client.ClientSecretHash, clientSecret!))
                {
                    logger.LogWarning(ServerLogEvents.ClientAuthFailed, "客户端认证失败：client={ClientId} 密钥不匹配", clientId);
                    return ClientAuthResult.Fail(StatusCodes.Status401Unauthorized, "invalid_client", "客户端认证失败", usedBasic);
                }
            }

            return ClientAuthResult.Ok(client, usedBasic);
        }

        /// <summary>
        /// 认证失败时写响应（invalid_client 时附带 WWW-Authenticate 头，RFC 6749 §5.2）。
        /// </summary>
        public static Task WriteFailureAsync(HttpContext context, ClientAuthResult result)
        {
            if (result.StatusCode == StatusCodes.Status401Unauthorized)
            {
                context.Response.Headers.WWWAuthenticate = "Basic realm=\"cyaim-auth-server\", charset=\"UTF-8\"";
            }
            return ServerHttp.WriteOAuthErrorAsync(context, result.StatusCode, result.Error ?? "invalid_client", result.ErrorDescription);
        }

        private static bool TryParseBasic(string encoded, out string? clientId, out string? clientSecret)
        {
            clientId = null;
            clientSecret = null;
            try
            {
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                int separator = decoded.IndexOf(':');
                if (separator < 0)
                {
                    return false;
                }
                // RFC 6749 §2.3.1：client_id 与 client_secret 均经 application/x-www-form-urlencoded 编码
                clientId = Uri.UnescapeDataString(decoded.Substring(0, separator));
                clientSecret = Uri.UnescapeDataString(decoded.Substring(separator + 1));
                return !string.IsNullOrEmpty(clientId);
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    /// <summary>
    /// 客户端认证结果。
    /// </summary>
    internal sealed class ClientAuthResult
    {
        /// <summary>认证通过的客户端（失败时为 null）</summary>
        public ClientApplication? Client { get; private set; }

        /// <summary>失败时的 HTTP 状态码（400/401）</summary>
        public int StatusCode { get; private set; }

        /// <summary>OAuth 错误码</summary>
        public string? Error { get; private set; }

        /// <summary>错误描述</summary>
        public string? ErrorDescription { get; private set; }

        /// <summary>是否使用了 Basic 认证头</summary>
        public bool UsedBasicAuth { get; private set; }

        /// <summary>是否成功</summary>
        public bool Success => Client != null;

        internal static ClientAuthResult Ok(ClientApplication client, bool usedBasic) =>
            new ClientAuthResult { Client = client, StatusCode = StatusCodes.Status200OK, UsedBasicAuth = usedBasic };

        internal static ClientAuthResult Fail(int statusCode, string error, string description, bool usedBasic) =>
            new ClientAuthResult { StatusCode = statusCode, Error = error, ErrorDescription = description, UsedBasicAuth = usedBasic };
    }
}
