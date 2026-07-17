using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Server.Endpoints;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// 授权服务器端点映射。
    /// </summary>
    public static class CyaimAuthServerEndpointRouteBuilderExtensions
    {
        private static readonly string[] GetAndPost = { "GET", "POST" };

        /// <summary>
        /// 映射授权服务器全部端点（发现文档、JWKS、令牌、授权、登录/登出、自省、吊销、用户信息）。
        /// 除 UserInfo 要求已认证外，其余端点带 AllowGuest 元数据以绕过权限中间件（各自完成客户端/用户认证）。
        /// 需先调用 <c>services.AddCyaimAuthentication()</c> 与 <c>services.AddCyaimAuthServer()</c>，
        /// 并在管道中启用 <c>app.UseCyaimAuthentication()</c>。
        /// </summary>
        public static IEndpointRouteBuilder MapCyaimAuthServer(this IEndpointRouteBuilder endpoints)
        {
            // OIDC 发现文档与 JWKS
            endpoints.MapGet(AuthConstants.Endpoints.Discovery, DiscoveryEndpoints.HandleDiscoveryAsync)
                .AllowGuest();
            endpoints.MapGet(AuthConstants.Endpoints.Jwks, DiscoveryEndpoints.HandleJwksAsync)
                .AllowGuest();

            // 令牌端点（RFC 6749）
            endpoints.MapPost(AuthConstants.Endpoints.Token, TokenEndpoint.HandleAsync)
                .AllowGuest();

            // 授权端点（授权码 + PKCE）
            endpoints.MapGet(AuthConstants.Endpoints.Authorize, AuthorizeEndpoint.HandleAsync)
                .AllowGuest();

            // 登录页
            endpoints.MapGet(AuthConstants.Endpoints.Login, AccountEndpoints.HandleLoginPageAsync)
                .AllowGuest();
            endpoints.MapPost(AuthConstants.Endpoints.Login, AccountEndpoints.HandleLoginSubmitAsync)
                .AllowGuest();

            // 登出与 OIDC 结束会话
            endpoints.MapMethods(AuthConstants.Endpoints.Logout, GetAndPost, AccountEndpoints.HandleLogoutAsync)
                .AllowGuest();
            endpoints.MapMethods(AuthConstants.Endpoints.EndSession, GetAndPost, AccountEndpoints.HandleLogoutAsync)
                .AllowGuest();

            // 令牌自省（RFC 7662）与吊销（RFC 7009）
            endpoints.MapPost(AuthConstants.Endpoints.Introspect, IntrospectionEndpoint.HandleAsync)
                .AllowGuest();
            endpoints.MapPost(AuthConstants.Endpoints.Revoke, RevocationEndpoint.HandleAsync)
                .AllowGuest();

            // 用户信息（OIDC UserInfo）：仅要求已认证
            endpoints.MapMethods(AuthConstants.Endpoints.UserInfo, GetAndPost, UserInfoEndpoint.HandleAsync)
                .RequirePermission();

            return endpoints;
        }
    }
}
