using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Cyaim.Authentication.Infrastructure;
using Cyaim.Authentication.Infrastructure.Attributes;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// 授权服务配置扩展
    /// </summary>
    public static class AuthServiceCollectionExtensions
    {
        /// <summary>
        /// 配置授权服务运行状态
        /// </summary>
        /// <param name="services"></param>
        /// <param name="setupAction"></param>
        public static void ConfigureAuth(this IServiceCollection services, Action<AuthOptions> setupAction)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            if (setupAction == null)
            {
                throw new ArgumentNullException(nameof(setupAction));
            }

            AuthOptions authOptions = new AuthOptions();
            setupAction(authOptions);
            services.AddSingleton(x => authOptions);

            services.TryAddSingleton<IAuthService, AuthenticationService>();

            ServiceProvider sp = services.BuildServiceProvider();
            IAuthService authService = sp.GetService<IAuthService>();

            Assembly assembly = null;
            if (string.IsNullOrEmpty(authOptions?.WatchAssemblyPath))
            {
                assembly = Assembly.GetEntryAssembly();
            }
            else
            {
                assembly = Assembly.LoadFile(authOptions.WatchAssemblyPath);
            }

            #region MyRegion

            ////加载授权节点
            //IEnumerable<AuthEndPointParm> authEndPointParms = new AuthEndPointParm[0];
            //string assemblyName = assembly.FullName.Split()[0]?.Trim(',') + ".Controllers";
            //var types = assembly.GetTypes().Where(x => !x.IsNestedPrivate && x.FullName.StartsWith(assemblyName)).ToList();
            //foreach (var item in types)
            //{
            //    var accessParm = authService.GetClassAccessParm(item);
            //    authEndPointParms = authEndPointParms.Union(accessParm);
            //    foreach (AuthEndPointParm parmItem in accessParm)
            //    {
            //        foreach (var attItem in parmItem.AuthEndPointAttributes)
            //        {
            //            if (attItem == null)
            //            {
            //                continue;
            //            }

            //            if (string.IsNullOrEmpty(attItem.AuthEndPoint))
            //            {
            //                attItem.AuthEndPoint = $"{parmItem.ControllerName}.{parmItem.ActionName}";
            //            }

            //            authService.RegisterAccessCode(attItem.AuthEndPoint, attItem.IsAllow);

            //            Console.WriteLine($"加载成功 -> {attItem.AuthEndPoint} 允许访问");
            //        }

            //    }

            //}

            //authOptions.WatchAuthEndPoint = authEndPointParms.ToArray();
            #endregion

            //正则匹配有鉴权攻击风险！！！   

            //加载授权节点
            List<AuthEndPointAttribute> authEndPointParms = new List<AuthEndPointAttribute>();
            string assemblyName = assembly.FullName.Split()[0]?.Trim(',') + ".Controllers";
            var types = assembly.GetTypes().Where(x => !x.IsNestedPrivate && x.FullName.StartsWith(assemblyName)).ToList();
            foreach (var item in types)
            {
                AuthEndPointAttribute[] accessParm = AuthServiceCollectionExtensions.GetClassAccessParm_AuthEndPointAttribute(item);
                authEndPointParms.AddRange(accessParm);
                foreach (AuthEndPointAttribute parmItem in accessParm)
                {
                    if (parmItem == null)
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(parmItem.AuthEndPoint))
                    {
                        parmItem.AuthEndPoint = $"{authOptions.PreAccessEndPointKey}:{parmItem.ControllerName}.{parmItem.ActionName}";
                    }

                    authService.RegisterAccessCode(parmItem.AuthEndPoint, parmItem.IsAllow);

                    Console.WriteLine($"权限节点加载成功 -> {parmItem.AuthEndPoint}");
                }

                AuthEnableRegexAttribute[] accessRegexParm = AuthServiceCollectionExtensions.GetClassAccessParm_AuthEnableRegexAttribute(item);
                foreach (AuthEnableRegexAttribute parmItem in accessRegexParm)
                {
                    if (parmItem == null)
                    {
                        continue;
                    }

                    parmItem.AuthEndPoint = $"{authOptions.PreAccessEndPointKey}:Regex⊇{parmItem.AuthEndPoint}";
                    authService.RegisterAccessCode(parmItem.AuthEndPoint, parmItem.IsAllow);

                    Console.WriteLine($"权限节点加载成功 -> {parmItem.AuthEndPoint}");
                }
            }


            authOptions.WatchAuthEndPoint = authEndPointParms.ToArray();


            //获取处理后的缓存并覆盖
            var memoryCache = sp.GetService<IMemoryCache>();

            var existService = services.FirstOrDefault(x => x.ServiceType == typeof(IMemoryCache));
            services.Remove(existService);

            services.TryAddSingleton<IMemoryCache>(x => memoryCache);
        }


        /// <summary>
        /// 获取程序集Controller中的权限节点
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static AuthEndPointAttribute[] GetClassAccessParm_AuthEndPointAttribute<T>()
        {
            var type = typeof(T);
            return GetClassAccessParm_AuthEndPointAttribute(type);
        }

        /// <summary>
        /// 获取程序集Controller中的权限节点
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static AuthEndPointAttribute[] GetClassAccessParm_AuthEndPointAttribute(Type type)
        {
            var classLevel = type.GetCustomAttributes<AuthEndPointAttribute>()
                  .Select(x =>
                  {
                      x.ActionName = "*";
                      x.ControllerName = type.Name;
                      return x;
                  });
            var methodLevel = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Select(x =>
                {
                    return x.GetCustomAttributes<AuthEndPointAttribute>().Select(a =>
                    {
                        a.ActionName = x.Name;
                        a.ControllerName = x.ReflectedType.Name;
                        a.Routes = x.GetCustomAttributes<AspNetCore.Mvc.Routing.HttpMethodAttribute>().ToArray();
                        a.ActionCanEmpty = a.Routes.Any(x => string.IsNullOrEmpty(x.Template));
                        return a;
                    }).ToArray();
                }).SelectMany((x, y) => x);


            return classLevel.Union(methodLevel).ToArray();
        }

        /// <summary>
        /// 获取程序集Controller中的权限节点
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static AuthEnableRegexAttribute[] GetClassAccessParm_AuthEnableRegexAttribute<T>()
        {
            var type = typeof(T);
            return GetClassAccessParm_AuthEnableRegexAttribute(type);
        }

        /// <summary>
        /// 获取程序集Controller中的权限节点
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static AuthEnableRegexAttribute[] GetClassAccessParm_AuthEnableRegexAttribute(Type type)
        {
            var classLevel = type.GetCustomAttributes<AuthEnableRegexAttribute>();

            return classLevel.ToArray();
        }

    }
}
