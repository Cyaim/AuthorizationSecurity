using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;

namespace Cyaim.Authentication.Abstractions.Services
{
    /// <summary>
    /// 权限评估器：框架鉴权核心入口。
    /// 实现应缓存每主体的编译权限集，并在存储版本变化时失效。
    /// </summary>
    public interface IPermissionEvaluator
    {
        /// <summary>
        /// 获取主体的编译权限集（合并直接授权与角色层级授权）。
        /// </summary>
        Task<CompiledPermissionSet> GetPermissionSetAsync(AuthSubject subject, CancellationToken cancellationToken = default);

        /// <summary>
        /// 尝试同步获取已缓存且未过期的权限集（热路径零异步开销）。
        /// </summary>
        bool TryGetCachedPermissionSet(AuthSubject subject, out CompiledPermissionSet permissionSet);

        /// <summary>
        /// 判断主体当前是否仍然有效（未被禁用/锁定，且令牌安全戳与存储一致）。
        /// 供仅要求"已认证"的端点在不检查具体权限时确认令牌未失效。
        /// </summary>
        Task<bool> IsSubjectActiveAsync(AuthSubject subject, CancellationToken cancellationToken = default);

        /// <summary>
        /// 判断主体是否拥有指定权限。
        /// </summary>
        Task<AuthorizationDecision> EvaluateAsync(AuthSubject subject, PermissionQuery permission, AuthorizationContext? context = null, CancellationToken cancellationToken = default);

        /// <summary>
        /// 评估命名策略（ABAC）。
        /// </summary>
        Task<AuthorizationDecision> EvaluatePolicyAsync(AuthSubject subject, string policyName, AuthorizationContext? context = null, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// <see cref="IPermissionEvaluator"/> 便捷扩展。
    /// </summary>
    public static class PermissionEvaluatorExtensions
    {
        /// <summary>
        /// 判断主体是否拥有指定权限代码。
        /// </summary>
        public static Task<AuthorizationDecision> EvaluateAsync(
            this IPermissionEvaluator evaluator, AuthSubject subject, string permissionCode,
            AuthorizationContext? context = null, CancellationToken cancellationToken = default)
        {
            if (!PermissionQuery.TryParse(permissionCode, out PermissionQuery query))
            {
                return Task.FromResult(AuthorizationDecision.Denied(AuthorizationReason.InvalidPermissionCode, permissionCode));
            }
            return evaluator.EvaluateAsync(subject, query, context, cancellationToken);
        }

        /// <summary>
        /// 判断主体是否拥有指定权限（仅布尔结果）。
        /// </summary>
        public static async Task<bool> IsGrantedAsync(
            this IPermissionEvaluator evaluator, AuthSubject subject, string permissionCode,
            CancellationToken cancellationToken = default)
        {
            AuthorizationDecision decision = await evaluator.EvaluateAsync(subject, permissionCode, null, cancellationToken).ConfigureAwait(false);
            return decision.IsGranted;
        }
    }
}
