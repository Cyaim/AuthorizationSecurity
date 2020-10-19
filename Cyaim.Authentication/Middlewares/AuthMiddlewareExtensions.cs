using Cyaim.Authentication.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Primitives;
using System;

namespace Cyaim.Authentication.Middlewares
{
    public static class AuthMiddlewareExtensions
    {
        public static IApplicationBuilder UseAuth(this IApplicationBuilder app)
        {
            app.UseMiddleware<AuthMiddleware>();

            return app;
        }
    }

}
