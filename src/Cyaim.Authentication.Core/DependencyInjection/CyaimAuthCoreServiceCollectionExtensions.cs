using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Audit;
using Cyaim.Authentication.Core.Cluster;
using Cyaim.Authentication.Core.Engine;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Core.Tokens;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 核心引擎 DI 注册。
    /// </summary>
    public static class CyaimAuthCoreServiceCollectionExtensions
    {
        /// <summary>
        /// 注册权限引擎核心服务（评估器、令牌服务、口令哈希、审计、策略注册表）。
        /// 通过返回的构建器链式注册存储与策略：
        /// <code>
        /// services.AddCyaimAuthCore(o => o.Issuer = "my-auth")
        ///     .AddInMemoryStore()
        ///     .AddPolicy("working-hours", ctx => ctx.Now.Hour is >= 9 and &lt; 18);
        /// </code>
        /// </summary>
        public static CyaimAuthCoreBuilder AddCyaimAuthCore(
            this IServiceCollection services, Action<CyaimAuthCoreOptions>? configure = null)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            services.AddOptions();
            services.AddLogging();
            if (configure != null)
            {
                services.Configure(configure);
            }

            services.TryAddSingleton<IAuthClock, SystemAuthClock>();
            services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
            services.TryAddSingleton(sp => new AuthPolicyRegistry(sp.GetServices<IAuthPolicy>()));
            services.TryAddSingleton<IPermissionEvaluator, PermissionEvaluator>();
            services.TryAddSingleton<ITokenService, JwtTokenService>();
            services.TryAddSingleton<IAuditLogger, DefaultAuditLogger>();
            services.TryAddSingleton<RefreshTokenManager>();
            services.TryAddSingleton<UserCredentialService>();
            services.TryAddSingleton<AuthDataSeeder>();

            return new CyaimAuthCoreBuilder(services);
        }
    }

    /// <summary>
    /// 核心引擎链式配置构建器。
    /// </summary>
    public sealed class CyaimAuthCoreBuilder
    {
        /// <summary>服务集合</summary>
        public IServiceCollection Services { get; }

        internal CyaimAuthCoreBuilder(IServiceCollection services)
        {
            Services = services;
        }

        /// <summary>
        /// 使用内存授权存储（测试、示例、小型部署）。
        /// </summary>
        public CyaimAuthCoreBuilder AddInMemoryStore()
        {
            Services.TryAddSingleton<InMemoryAuthStore>();
            return MapStore<InMemoryAuthStore>();
        }

        /// <summary>
        /// 使用 JSON 文件持久化存储。
        /// </summary>
        /// <param name="filePath">数据文件路径</param>
        public CyaimAuthCoreBuilder AddJsonFileStore(string filePath)
        {
            Services.TryAddSingleton(sp => new JsonFileAuthStore(filePath));
            return MapStore<JsonFileAuthStore>();
        }

        /// <summary>
        /// 将自定义存储实现映射到全部存储接口。
        /// </summary>
        public CyaimAuthCoreBuilder MapStore<TStore>()
            where TStore : class, IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion
        {
            Services.TryAddSingleton<IUserStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IRoleStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IClientStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IPermissionDefinitionStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<ITokenStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IAuthStoreVersion>(sp => sp.GetRequiredService<TStore>());
            return this;
        }

        /// <summary>
        /// 将自定义存储实现映射到五个**数据**存储接口，但**不**注册 <see cref="IAuthStoreVersion"/>——
        /// 版本改由 <see cref="AddClusterCacheInvalidation(IClusterVersionStore, Action{ClusterVersionOptions})"/>
        /// 提供的集群版本承担。集群部署（多实例共享数据库）时用本方法 + AddClusterCacheInvalidation。
        /// </summary>
        public CyaimAuthCoreBuilder MapDataStore<TStore>()
            where TStore : class, IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore
        {
            Services.TryAddSingleton<IUserStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IRoleStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IClientStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<IPermissionDefinitionStore>(sp => sp.GetRequiredService<TStore>());
            Services.TryAddSingleton<ITokenStore>(sp => sp.GetRequiredService<TStore>());
            return this;
        }

        /// <summary>
        /// 启用集群缓存失效：以 <see cref="ClusterAuthStoreVersion"/> 作为 <see cref="IAuthStoreVersion"/>，
        /// 通过共享的 <paramref name="versionStore"/>（如 Redis <c>INCR</c>）在多实例间同步授权数据版本，
        /// 使任一实例的授权变更在轮询间隔内让全集群权限集缓存失效。
        /// <para>
        /// 配合 <see cref="MapDataStore{TStore}"/>（共享数据库存储）使用。你的存储在每次写操作后应调用
        /// 注入的 <c>IAuthStoreVersion.Bump()</c>（如内置 InMemoryAuthStore 那样）以广播失效。
        /// </para>
        /// </summary>
        public CyaimAuthCoreBuilder AddClusterCacheInvalidation(
            IClusterVersionStore versionStore, Action<ClusterVersionOptions>? configure = null)
        {
            if (versionStore == null)
            {
                throw new ArgumentNullException(nameof(versionStore));
            }
            Services.AddSingleton(versionStore);
            return AddClusterCacheInvalidationCore(configure);
        }

        /// <summary>
        /// 启用集群缓存失效，共享版本存储由 DI 解析 <typeparamref name="TVersionStore"/> 得到。
        /// </summary>
        public CyaimAuthCoreBuilder AddClusterCacheInvalidation<TVersionStore>(Action<ClusterVersionOptions>? configure = null)
            where TVersionStore : class, IClusterVersionStore
        {
            Services.TryAddSingleton<IClusterVersionStore, TVersionStore>();
            return AddClusterCacheInvalidationCore(configure);
        }

        private CyaimAuthCoreBuilder AddClusterCacheInvalidationCore(Action<ClusterVersionOptions>? configure)
        {
            var options = new ClusterVersionOptions();
            configure?.Invoke(options);
            Services.AddSingleton(options);
            Services.AddSingleton<ClusterAuthStoreVersion>();
            // 覆盖任何已注册的 IAuthStoreVersion（如内置存储自带的本地版本）为集群版本
            Services.Replace(ServiceDescriptor.Singleton<IAuthStoreVersion>(
                sp => sp.GetRequiredService<ClusterAuthStoreVersion>()));
            return this;
        }

        /// <summary>
        /// 注册同步 ABAC 策略。
        /// </summary>
        public CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, bool> evaluate)
        {
            Services.AddSingleton<IAuthPolicy>(new DelegateAuthPolicy(name, evaluate));
            return this;
        }

        /// <summary>
        /// 注册异步 ABAC 策略。
        /// </summary>
        public CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate)
        {
            Services.AddSingleton<IAuthPolicy>(new DelegateAuthPolicy(name, evaluate));
            return this;
        }

        /// <summary>
        /// 注册策略类型。
        /// </summary>
        public CyaimAuthCoreBuilder AddPolicy<TPolicy>() where TPolicy : class, IAuthPolicy
        {
            Services.AddSingleton<IAuthPolicy, TPolicy>();
            return this;
        }
    }
}
