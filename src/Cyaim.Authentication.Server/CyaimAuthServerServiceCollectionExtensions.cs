using System;
using Cyaim.Authentication.Server;
using Cyaim.Authentication.Server.Sso;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 授权服务器 DI 注册。
    /// </summary>
    public static class CyaimAuthServerServiceCollectionExtensions
    {
        /// <summary>
        /// 注册独立授权服务器所需服务（SSO 会话等）。
        /// 必须先调用 <c>AddCyaimAuthentication()</c> 注册核心引擎与存储，本方法不重复注册这些服务：
        /// <code>
        /// builder.Services.AddCyaimAuthentication(o => { ... }).AddInMemoryStore();
        /// builder.Services.AddCyaimAuthServer(o => o.ServerName = "My Auth");
        /// // ...
        /// app.UseCyaimAuthentication();
        /// app.MapCyaimAuthServer();
        /// </code>
        /// </summary>
        /// <param name="services">服务集合</param>
        /// <param name="configure">服务器配置</param>
        public static IServiceCollection AddCyaimAuthServer(
            this IServiceCollection services, Action<CyaimAuthServerOptions>? configure = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure != null)
            {
                services.Configure(configure);
            }

            services.AddOptions();
            services.TryAddSingleton<SsoSessionService>();

            return services;
        }
    }
}
