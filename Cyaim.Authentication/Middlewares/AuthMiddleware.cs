using Cyaim.Authentication.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Middlewares
{
    /// <summary>
    /// 授权服务仅在本程序内运行
    /// </summary>
    public class AuthMiddleware
    {
        private readonly RequestDelegate _next;
        private IAuthService AuthService { get; }
        private ILogger Logger { get; }

        /// <summary>
        /// 授权配置，只加载在Startup中配置的数据
        /// </summary>
        public readonly IOptions<AuthOptions> _authOptions;

        public AuthMiddleware(
           IOptions<AuthOptions> authOptions,
           RequestDelegate next,
           IAuthService authService,
           ILoggerFactory loggerFactory)
        {

            if (next == null)
            {
                throw new ArgumentNullException(nameof(next));
            }

            if (authService == null)
            {
                throw new ArgumentNullException(nameof(authService));
            }

            if (loggerFactory == null)
            {
                throw new ArgumentNullException(nameof(loggerFactory));
            }

            if (authOptions == null)
            {
                throw new ArgumentNullException(nameof(authOptions));
            }

            _next = next;
            AuthService = authService;
            Logger = loggerFactory.CreateLogger<AuthMiddleware>();

            _authOptions = authOptions;
        }


        public async Task Invoke(HttpContext context)
        {

            bool hasCredential = await AuthService.CheckAuthorization(context);

            if (hasCredential)
            {
                await _next(context);
                return;
            }

            string token = AuthService.GetAuthorizationValue(context);
            Logger.LogWarning($"凭据 {token} -> {context.Request.Scheme}://{context.Request.Host}{context.Request.Path.Value} 无权限访问");

            var noAccessParm = _authOptions.Value.NonAccessParm;
            if (noAccessParm == null)
            {
                context.Response.StatusCode = 403;
                //context.Response.Body = new MemoryStream();
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync($@"{{
                    ""status"":403,
                    ""msg"":""无权限""
                }}");
            }
            else
            {
                context.Response.StatusCode = noAccessParm.NonAccessResponseStatus;
                context.Response.ContentType = noAccessParm.NonAccessResponseContentType;
                await context.Response.WriteAsync(noAccessParm.NonAccessResponseContent);
            }


            //return Task.CompletedTask;

            //await _next(context);
        }
    }
}
