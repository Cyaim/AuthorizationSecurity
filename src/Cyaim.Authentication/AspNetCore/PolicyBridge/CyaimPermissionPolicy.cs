using System;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core.Tokens;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.AspNetCore.PolicyBridge
{
    /// <summary>
    /// ASP.NET Core 原生授权系统桥接：
    /// <c>[Authorize(Policy = "cyaim:sys.user.read")]</c> 将由框架权限引擎评估。
    /// </summary>
    public sealed class CyaimPermissionRequirement : IAuthorizationRequirement
    {
        /// <summary>权限代码</summary>
        public string PermissionCode { get; }

        /// <summary>创建要求</summary>
        public CyaimPermissionRequirement(string permissionCode)
        {
            PermissionCode = permissionCode;
        }
    }

    /// <summary>
    /// 策略提供器：将 <c>cyaim:</c> 前缀的策略名解析为权限要求，其余委托默认提供器。
    /// </summary>
    public sealed class CyaimPermissionPolicyProvider : IAuthorizationPolicyProvider
    {
        /// <summary>策略名前缀</summary>
        public const string PolicyPrefix = "cyaim:";

        private readonly DefaultAuthorizationPolicyProvider _fallback;

        /// <summary>创建提供器</summary>
        public CyaimPermissionPolicyProvider(IOptions<AuthorizationOptions> options)
        {
            _fallback = new DefaultAuthorizationPolicyProvider(options);
        }

        /// <inheritdoc/>
        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

        /// <inheritdoc/>
        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();

        /// <inheritdoc/>
        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            if (policyName.StartsWith(PolicyPrefix, StringComparison.OrdinalIgnoreCase))
            {
                string code = policyName.Substring(PolicyPrefix.Length);
                AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
                    .AddRequirements(new CyaimPermissionRequirement(code))
                    .Build();
                return Task.FromResult<AuthorizationPolicy?>(policy);
            }

            return _fallback.GetPolicyAsync(policyName);
        }
    }

    /// <summary>
    /// 权限要求处理器：调用框架评估器。
    /// </summary>
    public sealed class CyaimPermissionAuthorizationHandler : AuthorizationHandler<CyaimPermissionRequirement>
    {
        private readonly IPermissionEvaluator _evaluator;

        /// <summary>创建处理器</summary>
        public CyaimPermissionAuthorizationHandler(IPermissionEvaluator evaluator)
        {
            _evaluator = evaluator;
        }

        /// <inheritdoc/>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, CyaimPermissionRequirement requirement)
        {
            AuthSubject subject;
            if (context.Resource is HttpContext httpContext)
            {
                subject = httpContext.GetAuthSubject();
            }
            else if (context.User.Identity is System.Security.Claims.ClaimsIdentity identity && identity.IsAuthenticated)
            {
                subject = AuthSubjectFactory.FromClaimsIdentity(identity);
            }
            else
            {
                subject = AuthSubject.Guest();
            }

            AuthorizationDecision decision = await _evaluator.EvaluateAsync(subject, requirement.PermissionCode);
            if (decision.IsGranted)
            {
                context.Succeed(requirement);
            }
        }
    }
}
