using Cyaim.Authentication.AspNetCore;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// 权限中间件注册扩展。
    /// </summary>
    public static class CyaimAuthApplicationBuilderExtensions
    {
        /// <summary>
        /// 启用权限中间件（须位于 UseRouting 之后；WebApplication 最简主机直接调用即可）。
        /// </summary>
        public static IApplicationBuilder UseCyaimAuthentication(this IApplicationBuilder app)
        {
            // 捕获端点数据源，供启动后权限扫描（WebApplication 同时实现 IEndpointRouteBuilder）
            if (app is IEndpointRouteBuilder routeBuilder)
            {
                var accessor = app.ApplicationServices.GetService<EndpointDataSourceAccessor>();
                if (accessor != null)
                {
                    accessor.Sources = routeBuilder.DataSources;
                }
            }

            return app.UseMiddleware<CyaimAuthMiddleware>();
        }
    }
}
