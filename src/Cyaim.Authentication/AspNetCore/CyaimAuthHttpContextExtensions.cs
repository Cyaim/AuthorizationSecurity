using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.AspNetCore;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Http
{
    /// <summary>
    /// HttpContext 鉴权便捷扩展。
    /// </summary>
    public static class CyaimAuthHttpContextExtensions
    {
        /// <summary>
        /// 获取当前请求主体（中间件已解析；未认证返回游客）。
        /// </summary>
        public static AuthSubject GetAuthSubject(this HttpContext context)
        {
            return context.Features.Get<ICyaimAuthFeature>()?.Subject ?? AuthSubject.Guest();
        }

        /// <summary>
        /// 当前请求令牌状态。
        /// </summary>
        public static TokenState GetTokenState(this HttpContext context)
        {
            return context.Features.Get<ICyaimAuthFeature>()?.TokenState ?? TokenState.None;
        }

        /// <summary>
        /// 命令式权限检查（WebSocket 消息循环、业务内细粒度判断用）。
        /// </summary>
        public static Task<AuthorizationDecision> CheckPermissionAsync(this HttpContext context, string permissionCode)
        {
            IPermissionEvaluator evaluator = context.RequestServices.GetRequiredService<IPermissionEvaluator>();
            return evaluator.EvaluateAsync(context.GetAuthSubject(), permissionCode, null, context.RequestAborted);
        }

        /// <summary>
        /// 命令式权限检查（仅布尔结果）。
        /// </summary>
        public static async Task<bool> HasPermissionAsync(this HttpContext context, string permissionCode)
        {
            AuthorizationDecision decision = await context.CheckPermissionAsync(permissionCode);
            return decision.IsGranted;
        }
    }
}
