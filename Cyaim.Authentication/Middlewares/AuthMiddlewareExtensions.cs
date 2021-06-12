using Cyaim.Authentication.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Primitives;
using System;

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
        /// <returns></returns>
        public static IApplicationBuilder UseAuth(this IApplicationBuilder app)
        {
            app.UseMiddleware<AuthMiddleware>();

            return app;
        }
    }

}
