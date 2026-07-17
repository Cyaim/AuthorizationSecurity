using System.Collections.Generic;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// OIDC 发现文档与 JWKS 端点。
    /// </summary>
    internal static class DiscoveryEndpoints
    {
        /// <summary>
        /// GET /.well-known/openid-configuration
        /// </summary>
        public static async Task HandleDiscoveryAsync(HttpContext context)
        {
            var options = context.RequestServices.GetRequiredService<IOptions<CyaimAuthServerOptions>>().Value;
            var tokenService = context.RequestServices.GetRequiredService<ITokenService>();
            string origin = ServerHttp.GetOrigin(context, options);

            var grantTypes = new List<string>();
            if (options.EnableAuthorizationCode)
            {
                grantTypes.Add(AuthConstants.GrantTypes.AuthorizationCode);
            }
            if (options.EnableClientCredentials)
            {
                grantTypes.Add(AuthConstants.GrantTypes.ClientCredentials);
            }
            if (options.EnablePasswordGrant)
            {
                grantTypes.Add(AuthConstants.GrantTypes.Password);
            }
            if (options.EnableRefreshTokens)
            {
                grantTypes.Add(AuthConstants.GrantTypes.RefreshToken);
            }

            var document = new Dictionary<string, object?>
            {
                ["issuer"] = tokenService.Issuer,
                ["authorization_endpoint"] = origin + AuthConstants.Endpoints.Authorize,
                ["token_endpoint"] = origin + AuthConstants.Endpoints.Token,
                ["userinfo_endpoint"] = origin + AuthConstants.Endpoints.UserInfo,
                ["introspection_endpoint"] = origin + AuthConstants.Endpoints.Introspect,
                ["revocation_endpoint"] = origin + AuthConstants.Endpoints.Revoke,
                ["end_session_endpoint"] = origin + AuthConstants.Endpoints.EndSession,
                ["jwks_uri"] = origin + AuthConstants.Endpoints.Jwks,
                ["grant_types_supported"] = grantTypes,
                ["response_types_supported"] = new[] { "code" },
                ["scopes_supported"] = new[]
                {
                    AuthConstants.Scopes.OpenId,
                    AuthConstants.Scopes.Profile,
                    AuthConstants.Scopes.OfflineAccess,
                    AuthConstants.Scopes.Permissions,
                },
                ["token_endpoint_auth_methods_supported"] = new[] { "client_secret_basic", "client_secret_post" },
                ["code_challenge_methods_supported"] = new[] { "S256" },
            };

            await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK, document).ConfigureAwait(false);
        }

        /// <summary>
        /// GET /.well-known/jwks
        /// </summary>
        public static async Task HandleJwksAsync(HttpContext context)
        {
            var tokenService = context.RequestServices.GetRequiredService<ITokenService>();
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsync(tokenService.GetJwksJson(), context.RequestAborted).ConfigureAwait(false);
        }
    }
}
