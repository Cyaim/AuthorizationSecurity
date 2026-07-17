using System;
using Cyaim.Authentication.AdminPanel;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// 管理面板端点注册。
    /// </summary>
    public static class CyaimAuthAdminEndpointRouteBuilderExtensions
    {
        /// <summary>
        /// 挂载权限管理面板（内嵌 SPA + 管理 REST API）到 <see cref="CyaimAuthAdminOptions.BasePath"/>。
        /// 需与 UseCyaimAuthentication 中间件配合以执行端点鉴权。
        /// <code>app.MapCyaimAuthAdmin();</code>
        /// </summary>
        public static RouteGroupBuilder MapCyaimAuthAdmin(this IEndpointRouteBuilder endpoints)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }

            CyaimAuthAdminOptions options = endpoints.ServiceProvider
                .GetRequiredService<IOptions<CyaimAuthAdminOptions>>().Value;
            RouteGroupBuilder group = endpoints.MapGroup(NormalizeBasePath(options.BasePath));

            AdminApiEndpoints.Map(group);
            AdminStaticEndpoints.Map(group);
            return group;
        }

        private static string NormalizeBasePath(string? basePath)
        {
            if (string.IsNullOrWhiteSpace(basePath) || basePath == "/")
            {
                return string.Empty;
            }
            string path = basePath!.Trim().TrimEnd('/');
            return path.StartsWith("/", StringComparison.Ordinal) ? path : "/" + path;
        }
    }
}
