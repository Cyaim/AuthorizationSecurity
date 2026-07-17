using System;
using Cyaim.Authentication.AdminPanel;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 管理面板 DI 注册。
    /// </summary>
    public static class CyaimAuthAdminServiceCollectionExtensions
    {
        /// <summary>
        /// 注册权限管理面板（需已调用 AddCyaimAuthentication 并配置存储）。
        /// <code>
        /// builder.Services.AddCyaimAuthAdminPanel(o => o.BasePath = "/auth-admin");
        /// app.MapCyaimAuthAdmin();
        /// </code>
        /// </summary>
        public static IServiceCollection AddCyaimAuthAdminPanel(
            this IServiceCollection services, Action<CyaimAuthAdminOptions>? configure = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure != null)
            {
                services.Configure(configure);
            }

            return services;
        }
    }
}
