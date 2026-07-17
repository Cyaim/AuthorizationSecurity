using System.Collections.Generic;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 用户信息端点 GET|POST /connect/userinfo（OIDC UserInfo）。
    /// 端点带 RequirePermission 元数据（无参 = 仅要求已认证），主体由权限中间件解析。
    /// </summary>
    internal static class UserInfoEndpoint
    {
        /// <summary>
        /// 处理用户信息请求。
        /// </summary>
        public static async Task HandleAsync(HttpContext context)
        {
            AuthSubject subject = context.GetAuthSubject();

            var evaluator = context.RequestServices.GetRequiredService<IPermissionEvaluator>();
            CompiledPermissionSet permissionSet = await evaluator.GetPermissionSetAsync(subject, context.RequestAborted).ConfigureAwait(false);

            var payload = new Dictionary<string, object?>
            {
                ["sub"] = subject.Id,
                ["role"] = subject.Roles,
                ["permissions"] = permissionSet.Allows,
                ["scope"] = string.Join(" ", subject.Scopes),
            };
            if (!string.IsNullOrEmpty(subject.Name))
            {
                payload["name"] = subject.Name;
            }
            if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.PreferredUserName, out string? userName))
            {
                payload["preferred_username"] = userName;
            }
            if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.Email, out string? email))
            {
                payload["email"] = email;
            }

            await ServerHttp.WriteJsonAsync(context, StatusCodes.Status200OK, payload).ConfigureAwait(false);
        }
    }
}
