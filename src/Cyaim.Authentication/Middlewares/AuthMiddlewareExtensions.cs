#nullable disable
﻿using Cyaim.Authentication.Infrastructure;
using Cyaim.Authentication.Infrastructure.Attributes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Middlewares
{
    /// <summary>
    /// 
    /// </summary>
    public static class AuthMiddlewareExtensions
    {
        /// <summary>
        ///
        /// </summary>
        /// <param name="app"></param>
        /// <param name="setupAction"></param>
        /// <returns></returns>
        [Obsolete("1.x 遗留 API。请改用 app.UseCyaimAuthentication()。")]
        public static IApplicationBuilder UseAuth(this IApplicationBuilder app, Action<AuthOptions> setupAction)
        {
            app.UseMiddleware<AuthMiddleware>();

            IAuthService authService = app.ApplicationServices.GetService<IAuthService>();


            var authOptionsTemp = app.ApplicationServices.GetRequiredService<IOptionsMonitor<AuthOptions>>();
            var authOptions = authOptionsTemp.Get(AuthServiceCollectionExtensions.AuthOptionsKey);

            setupAction.Invoke(authOptions);

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


            authService.AuthOptions = authOptions;

            //获取处理后的缓存并覆盖
            //var memoryCache = sp.GetService<IMemoryCache>();

            //var existService = services.FirstOrDefault(x => x.ServiceType == typeof(IMemoryCache));
            //services.Remove(existService);

            //services.TryAddSingleton<IMemoryCache>(x => memoryCache);

            return app;
        }
    }

}