using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.AspNetCore;
using Cyaim.Authentication.AspNetCore.PolicyBridge;
using Cyaim.Authentication.Core;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// ASP.NET Core 集成 DI 注册。
    /// </summary>
    public static class CyaimAuthenticationServiceCollectionExtensions
    {
        /// <summary>
        /// 注册权限框架（核心引擎 + ASP.NET Core 集成）。
        /// <code>
        /// builder.Services.AddCyaimAuthentication(o =>
        /// {
        ///     o.Issuer = "https://auth.example.com";
        ///     o.HmacSigningKey = "至少32字节的签名密钥................";
        /// }).AddInMemoryStore();
        /// </code>
        /// </summary>
        public static CyaimAuthAspNetBuilder AddCyaimAuthentication(
            this IServiceCollection services, Action<CyaimAuthOptions>? configure = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (configure != null)
            {
                services.Configure(configure);
            }

            // 核心引擎读取 CyaimAuthCoreOptions —— 从 ASP.NET 集成配置镜像同步
            services.AddSingleton<IConfigureOptions<CyaimAuthCoreOptions>>(sp =>
                new ConfigureOptions<CyaimAuthCoreOptions>(core =>
                    CopyCoreOptions(sp.GetRequiredService<IOptions<CyaimAuthOptions>>().Value, core)));

            CyaimAuthCoreBuilder coreBuilder = services.AddCyaimAuthCore();

            services.TryAddSingleton<EndpointPermissionResolver>();
            services.TryAddSingleton<EndpointDataSourceAccessor>();
            services.AddHostedService<EndpointPermissionScanner>();

            // 原生 [Authorize(Policy = "cyaim:xxx")] 桥接
            services.AddSingleton<IAuthorizationHandler, CyaimPermissionAuthorizationHandler>();
            ServiceDescriptor? existing = services.FirstOrDefault(d => d.ServiceType == typeof(IAuthorizationPolicyProvider));
            if (existing == null)
            {
                services.AddSingleton<IAuthorizationPolicyProvider, CyaimPermissionPolicyProvider>();
            }
            else if (existing.ImplementationType == typeof(DefaultAuthorizationPolicyProvider))
            {
                services.Replace(ServiceDescriptor.Singleton<IAuthorizationPolicyProvider, CyaimPermissionPolicyProvider>());
            }

            return new CyaimAuthAspNetBuilder(coreBuilder);
        }

        private static void CopyCoreOptions(CyaimAuthOptions source, CyaimAuthCoreOptions target)
        {
            target.Issuer = source.Issuer;
            target.Audience = source.Audience;
            target.HmacSigningKey = source.HmacSigningKey;
            target.RsaKeyFilePath = source.RsaKeyFilePath;
            target.DefaultAccessTokenLifetime = source.DefaultAccessTokenLifetime;
            target.DefaultRefreshTokenLifetime = source.DefaultRefreshTokenLifetime;
            target.ClockSkew = source.ClockSkew;
            target.GuestRoles = new List<string>(source.GuestRoles);
            target.PermissionCacheTtl = source.PermissionCacheTtl;
            target.MaxCachedPermissionSets = source.MaxCachedPermissionSets;
            target.IncludePermissionsInToken = source.IncludePermissionsInToken;
            target.AuditCapacity = source.AuditCapacity;
            target.AuditFilePath = source.AuditFilePath;
            target.MaxAccessFailedCount = source.MaxAccessFailedCount;
            target.LockoutDuration = source.LockoutDuration;
        }
    }

    /// <summary>
    /// ASP.NET Core 集成链式配置构建器（代理核心构建器的存储与策略注册）。
    /// </summary>
    public sealed class CyaimAuthAspNetBuilder
    {
        private readonly CyaimAuthCoreBuilder _core;

        internal CyaimAuthAspNetBuilder(CyaimAuthCoreBuilder core)
        {
            _core = core;
        }

        /// <summary>服务集合</summary>
        public IServiceCollection Services => _core.Services;

        /// <summary>核心构建器</summary>
        public CyaimAuthCoreBuilder Core => _core;

        /// <inheritdoc cref="CyaimAuthCoreBuilder.AddInMemoryStore"/>
        public CyaimAuthAspNetBuilder AddInMemoryStore()
        {
            _core.AddInMemoryStore();
            return this;
        }

        /// <inheritdoc cref="CyaimAuthCoreBuilder.AddJsonFileStore"/>
        public CyaimAuthAspNetBuilder AddJsonFileStore(string filePath)
        {
            _core.AddJsonFileStore(filePath);
            return this;
        }

        /// <inheritdoc cref="CyaimAuthCoreBuilder.MapStore{TStore}"/>
        public CyaimAuthAspNetBuilder MapStore<TStore>()
            where TStore : class,
                Cyaim.Authentication.Abstractions.Stores.IUserStore,
                Cyaim.Authentication.Abstractions.Stores.IRoleStore,
                Cyaim.Authentication.Abstractions.Stores.IClientStore,
                Cyaim.Authentication.Abstractions.Stores.IPermissionDefinitionStore,
                Cyaim.Authentication.Abstractions.Stores.ITokenStore,
                Cyaim.Authentication.Abstractions.Stores.IAuthStoreVersion
        {
            _core.MapStore<TStore>();
            return this;
        }

        /// <inheritdoc cref="CyaimAuthCoreBuilder.AddPolicy(string, Func{AuthorizationContext, bool})"/>
        public CyaimAuthAspNetBuilder AddPolicy(string name, Func<AuthorizationContext, bool> evaluate)
        {
            _core.AddPolicy(name, evaluate);
            return this;
        }

        /// <inheritdoc cref="CyaimAuthCoreBuilder.AddPolicy(string, Func{AuthorizationContext, CancellationToken, Task{bool}})"/>
        public CyaimAuthAspNetBuilder AddPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate)
        {
            _core.AddPolicy(name, evaluate);
            return this;
        }

        /// <inheritdoc cref="CyaimAuthCoreBuilder.AddPolicy{TPolicy}"/>
        public CyaimAuthAspNetBuilder AddPolicy<TPolicy>() where TPolicy : class, IAuthPolicy
        {
            _core.AddPolicy<TPolicy>();
            return this;
        }
    }
}
