#nullable disable
﻿using System;
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
        public const string AuthOptionsKey = "AuthOptions";

        /// <summary>
        /// 配置授权服务运行状态
        /// </summary>
        /// <param name="services"></param>
        /// <param name="setupAction"></param>
        [Obsolete("1.x 遗留 API。请改用 services.AddCyaimAuthentication(...)。")]
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

            services.Configure(AuthOptionsKey, setupAction);

            AuthOptions options = new AuthOptions();
            setupAction.Invoke(options);

            services.TryAddSingleton(options);
            services.TryAddSingleton<IAuthService, AuthenticationService>();
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