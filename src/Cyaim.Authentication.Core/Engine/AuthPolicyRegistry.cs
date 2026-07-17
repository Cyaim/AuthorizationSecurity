using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;

namespace Cyaim.Authentication.Core.Engine
{
    /// <summary>
    /// 命名 ABAC 策略注册表（不区分大小写）。
    /// </summary>
    public sealed class AuthPolicyRegistry
    {
        private readonly Dictionary<string, IAuthPolicy> _policies;

        /// <summary>
        /// 从 DI 注入的策略集合构建注册表。
        /// </summary>
        public AuthPolicyRegistry(IEnumerable<IAuthPolicy> policies)
        {
            _policies = new Dictionary<string, IAuthPolicy>(StringComparer.OrdinalIgnoreCase);
            foreach (IAuthPolicy policy in policies)
            {
                _policies[policy.Name] = policy;
            }
        }

        /// <summary>按名称查找策略</summary>
        public IAuthPolicy? Find(string name)
        {
            _policies.TryGetValue(name, out IAuthPolicy? policy);
            return policy;
        }

        /// <summary>已注册的策略名</summary>
        public IReadOnlyCollection<string> Names => _policies.Keys;
    }

    /// <summary>
    /// 委托式 ABAC 策略。
    /// </summary>
    public sealed class DelegateAuthPolicy : IAuthPolicy
    {
        private readonly Func<AuthorizationContext, CancellationToken, Task<bool>> _evaluate;

        /// <summary>创建异步委托策略</summary>
        public DelegateAuthPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            _evaluate = evaluate ?? throw new ArgumentNullException(nameof(evaluate));
        }

        /// <summary>创建同步委托策略</summary>
        public DelegateAuthPolicy(string name, Func<AuthorizationContext, bool> evaluate)
            : this(name, (ctx, _) => Task.FromResult(evaluate(ctx)))
        {
        }

        /// <inheritdoc/>
        public string Name { get; }

        /// <inheritdoc/>
        public Task<bool> EvaluateAsync(AuthorizationContext context, CancellationToken cancellationToken = default) =>
            _evaluate(context, cancellationToken);
    }
}
