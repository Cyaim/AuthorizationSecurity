using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Core.Engine
{
    /// <summary>
    /// 权限评估器默认实现。
    /// <para>
    /// 每主体的有效权限（直接授权 ∪ 角色层级授权）编译为 <see cref="CompiledPermissionSet"/> 并缓存；
    /// 存储版本号变化或 TTL 到期时重建。热路径（缓存命中）为纯同步 O(1)/O(段数) 查找，零分配。
    /// </para>
    /// </summary>
    public sealed class PermissionEvaluator : IPermissionEvaluator
    {
        private readonly CyaimAuthCoreOptions _options;
        private readonly IAuthClock _clock;
        private readonly ILogger<PermissionEvaluator> _logger;
        private readonly AuthPolicyRegistry _policies;
        private readonly IUserStore? _userStore;
        private readonly IRoleStore? _roleStore;
        private readonly IClientStore? _clientStore;
        private readonly IAuthStoreVersion? _storeVersion;

        private readonly ConcurrentDictionary<string, CacheEntry> _cache = new ConcurrentDictionary<string, CacheEntry>(StringComparer.Ordinal);
        private volatile RoleGraph? _roleGraph;

        private sealed class CacheEntry
        {
            public CompiledPermissionSet Set = CompiledPermissionSet.Empty;
            public long Version;
            public DateTimeOffset ExpiresAt;
            public bool SubjectDisabled;
        }

        private sealed class RoleGraph
        {
            public Dictionary<string, AuthRole> ByName = new Dictionary<string, AuthRole>(StringComparer.OrdinalIgnoreCase);
            public long Version;
            public DateTimeOffset ExpiresAt;
        }

        /// <summary>
        /// 创建评估器。存储接口均为可选：未注册用户/角色存储时，回退到主体自带的令牌声明。
        /// </summary>
        public PermissionEvaluator(
            IOptions<CyaimAuthCoreOptions> options,
            IAuthClock clock,
            ILogger<PermissionEvaluator> logger,
            AuthPolicyRegistry policies,
            IServiceProvider serviceProvider)
        {
            _options = options.Value;
            _clock = clock;
            _logger = logger;
            _policies = policies;
            _userStore = (IUserStore?)serviceProvider.GetService(typeof(IUserStore));
            _roleStore = (IRoleStore?)serviceProvider.GetService(typeof(IRoleStore));
            _clientStore = (IClientStore?)serviceProvider.GetService(typeof(IClientStore));
            _storeVersion = (IAuthStoreVersion?)serviceProvider.GetService(typeof(IAuthStoreVersion));
        }

        private long CurrentVersion => _storeVersion?.Version ?? 0;

        /// <inheritdoc/>
        public bool TryGetCachedPermissionSet(AuthSubject subject, out CompiledPermissionSet permissionSet)
        {
            if (TryGetValidEntry(BuildCacheKey(subject), out CacheEntry? entry))
            {
                permissionSet = entry!.Set;
                return true;
            }

            permissionSet = CompiledPermissionSet.Empty;
            return false;
        }

        /// <inheritdoc/>
        public async Task<CompiledPermissionSet> GetPermissionSetAsync(AuthSubject subject, CancellationToken cancellationToken = default)
        {
            CacheEntry entry = await GetOrBuildEntryAsync(subject, cancellationToken).ConfigureAwait(false);
            return entry.Set;
        }

        /// <inheritdoc/>
        public async Task<bool> IsSubjectActiveAsync(AuthSubject subject, CancellationToken cancellationToken = default)
        {
            if (!subject.IsAuthenticated)
            {
                return false;
            }
            CacheEntry entry = await GetOrBuildEntryAsync(subject, cancellationToken).ConfigureAwait(false);
            return !entry.SubjectDisabled;
        }

        /// <inheritdoc/>
        public async Task<AuthorizationDecision> EvaluateAsync(
            AuthSubject subject, PermissionQuery permission,
            AuthorizationContext? context = null, CancellationToken cancellationToken = default)
        {
            long startTimestamp = Stopwatch.GetTimestamp();

            string cacheKey = BuildCacheKey(subject);
            CacheEntry? entry;
            bool cacheHit = TryGetValidEntry(cacheKey, out entry);
            if (!cacheHit)
            {
                entry = await GetOrBuildEntryAsync(subject, cancellationToken).ConfigureAwait(false);
            }

            AuthorizationDecision decision;
            if (entry!.SubjectDisabled)
            {
                decision = AuthorizationDecision.Denied(AuthorizationReason.SubjectDisabled, permission.Code);
            }
            else
            {
                PermissionEffect effect = entry.Set.Evaluate(permission);
                decision = effect switch
                {
                    PermissionEffect.Allow => AuthorizationDecision.Granted(AuthorizationReason.Granted, permission.Code),
                    PermissionEffect.Deny => AuthorizationDecision.Denied(AuthorizationReason.DeniedByRule, permission.Code),
                    _ => subject.IsAuthenticated
                        ? AuthorizationDecision.Denied(AuthorizationReason.NoMatchingGrant, permission.Code)
                        : AuthorizationDecision.Denied(AuthorizationReason.GuestNotAllowed, permission.Code),
                };
            }

            double elapsedMs = GetElapsedMilliseconds(startTimestamp);
            AuthMetrics.RecordCheck(decision.IsGranted, cacheHit, elapsedMs);

            if (!decision.IsGranted)
            {
                _logger.LogDebug(AuthLogEvents.PermissionDenied,
                    "权限拒绝 subject={SubjectId} permission={Permission} reason={Reason} elapsed={ElapsedMs}ms",
                    subject.Id, permission.Code, decision.Reason, elapsedMs);
            }

            return decision;
        }

        /// <inheritdoc/>
        public async Task<AuthorizationDecision> EvaluatePolicyAsync(
            AuthSubject subject, string policyName,
            AuthorizationContext? context = null, CancellationToken cancellationToken = default)
        {
            IAuthPolicy? policy = _policies.Find(policyName);
            if (policy == null)
            {
                _logger.LogWarning(AuthLogEvents.PolicyNotFound, "策略不存在 policy={Policy}，按拒绝处理", policyName);
                return AuthorizationDecision.Denied(AuthorizationReason.PolicyNotFound, policyName: policyName);
            }

            context ??= new AuthorizationContext { Subject = subject, Now = _clock.UtcNow };

            try
            {
                bool satisfied = await policy.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
                return satisfied
                    ? AuthorizationDecision.Granted(AuthorizationReason.GrantedByPolicy, policyName: policyName)
                    : AuthorizationDecision.Denied(AuthorizationReason.PolicyNotSatisfied, policyName: policyName);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // 策略异常按拒绝处理（fail-closed）
                _logger.LogError(AuthLogEvents.PolicyError, ex, "策略评估异常 policy={Policy}，按拒绝处理", policyName);
                return AuthorizationDecision.Denied(AuthorizationReason.PolicyNotSatisfied, policyName: policyName);
            }
        }

        /// <summary>
        /// 立即清空全部缓存（数据批量导入后可调用）。
        /// </summary>
        public void InvalidateAll()
        {
            _cache.Clear();
            _roleGraph = null;
        }

        #region 权限集构建

        private bool TryGetValidEntry(string cacheKey, out CacheEntry? entry)
        {
            if (_cache.TryGetValue(cacheKey, out entry) &&
                entry.Version == CurrentVersion &&
                entry.ExpiresAt > _clock.UtcNow)
            {
                return true;
            }

            entry = null;
            return false;
        }

        private async Task<CacheEntry> GetOrBuildEntryAsync(AuthSubject subject, CancellationToken cancellationToken)
        {
            string cacheKey = BuildCacheKey(subject);
            if (TryGetValidEntry(cacheKey, out CacheEntry? cached))
            {
                return cached!;
            }

            CacheEntry entry = await BuildEntryAsync(subject, cancellationToken).ConfigureAwait(false);

            if (_cache.Count >= _options.MaxCachedPermissionSets)
            {
                _logger.LogInformation(AuthLogEvents.CacheReset, "权限集缓存超过上限 {Max}，整体清空", _options.MaxCachedPermissionSets);
                _cache.Clear();
            }
            _cache[cacheKey] = entry;
            return entry;
        }

        private async Task<CacheEntry> BuildEntryAsync(AuthSubject subject, CancellationToken cancellationToken)
        {
            long version = CurrentVersion;
            DateTimeOffset now = _clock.UtcNow;
            var allows = new List<string>();
            var denies = new List<string>();
            IEnumerable<string> roleNames = subject.Roles;
            bool disabled = false;

            switch (subject.SubjectType)
            {
                case AuthSubjectType.User when subject.IsAuthenticated && _userStore != null:
                    {
                        AuthUser? user = await _userStore.FindByIdAsync(subject.Id, cancellationToken).ConfigureAwait(false);
                        if (user != null)
                        {
                            if (!user.IsEnabled || user.IsLockedOut(now))
                            {
                                disabled = true;
                                break;
                            }
                            // 安全戳校验：令牌携带的 sstamp 与用户当前安全戳不一致，说明口令/授权
                            // 已发生重大变更（口令重置、账户禁用/授权收紧），旧令牌应立即失效。
                            if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.SecurityStamp, out string? tokenStamp) &&
                                !string.IsNullOrEmpty(tokenStamp) &&
                                !string.Equals(tokenStamp, user.SecurityStamp, StringComparison.Ordinal))
                            {
                                _logger.LogWarning(AuthLogEvents.PermissionDenied,
                                    "主体 {SubjectId} 令牌安全戳过期，判定为失效令牌", subject.Id);
                                disabled = true;
                                break;
                            }
                            // 存储数据优先于令牌声明（支持实时授权变更）
                            allows.AddRange(user.DirectPermissions);
                            denies.AddRange(user.DeniedPermissions);
                            roleNames = user.Roles;
                        }
                        else
                        {
                            // 本地无此用户（分布式资源服务场景）：信任令牌声明
                            allows.AddRange(subject.DirectPermissions);
                            denies.AddRange(subject.DeniedPermissions);
                        }
                        break;
                    }

                case AuthSubjectType.Client when _clientStore != null:
                    {
                        ClientApplication? client = await _clientStore.FindByClientIdAsync(subject.Id, cancellationToken).ConfigureAwait(false);
                        if (client != null)
                        {
                            if (!client.Enabled)
                            {
                                disabled = true;
                                break;
                            }
                            allows.AddRange(client.Permissions);
                        }
                        else
                        {
                            allows.AddRange(subject.DirectPermissions);
                            denies.AddRange(subject.DeniedPermissions);
                        }
                        break;
                    }

                default:
                    allows.AddRange(subject.DirectPermissions);
                    denies.AddRange(subject.DeniedPermissions);
                    break;
            }

            if (!disabled)
            {
                if (!subject.IsAuthenticated && _options.GuestRoles.Count > 0)
                {
                    var merged = new List<string>(_options.GuestRoles);
                    merged.AddRange(roleNames);
                    roleNames = merged;
                }

                await FlattenRolesAsync(roleNames, allows, denies, cancellationToken).ConfigureAwait(false);
            }

            var entry = new CacheEntry
            {
                Set = disabled
                    ? CompiledPermissionSet.Empty
                    : CompiledPermissionSet.Build(allows, denies, version),
                Version = version,
                ExpiresAt = now + _options.PermissionCacheTtl,
                SubjectDisabled = disabled,
            };

            _logger.LogDebug(AuthLogEvents.PermissionSetBuilt,
                "编译权限集 subject={SubjectId} allows={AllowCount} denies={DenyCount} version={Version}",
                subject.Id, entry.Set.Allows.Count, entry.Set.Denies.Count, version);

            return entry;
        }

        /// <summary>
        /// 按角色层级（BFS，环安全）展开权限。
        /// </summary>
        private async Task FlattenRolesAsync(IEnumerable<string> roleNames, List<string> allows, List<string> denies, CancellationToken cancellationToken)
        {
            if (_roleStore == null)
            {
                return;
            }

            RoleGraph graph = await GetRoleGraphAsync(cancellationToken).ConfigureAwait(false);
            if (graph.ByName.Count == 0)
            {
                return;
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var queue = new Queue<string>();
            foreach (string name in roleNames)
            {
                if (!string.IsNullOrWhiteSpace(name) && visited.Add(name))
                {
                    queue.Enqueue(name);
                }
            }

            while (queue.Count > 0)
            {
                string name = queue.Dequeue();
                if (!graph.ByName.TryGetValue(name, out AuthRole? role))
                {
                    continue;
                }

                allows.AddRange(role.Permissions);
                denies.AddRange(role.DeniedPermissions);

                foreach (string parent in role.ParentRoles)
                {
                    if (!string.IsNullOrWhiteSpace(parent) && visited.Add(parent))
                    {
                        queue.Enqueue(parent);
                    }
                }
            }
        }

        private async Task<RoleGraph> GetRoleGraphAsync(CancellationToken cancellationToken)
        {
            RoleGraph? graph = _roleGraph;
            long version = CurrentVersion;
            DateTimeOffset now = _clock.UtcNow;
            if (graph != null && graph.Version == version && graph.ExpiresAt > now)
            {
                return graph;
            }

            IReadOnlyList<AuthRole> roles = await _roleStore!.GetAllAsync(cancellationToken).ConfigureAwait(false);
            var byName = new Dictionary<string, AuthRole>(roles.Count, StringComparer.OrdinalIgnoreCase);
            foreach (AuthRole role in roles)
            {
                byName[role.Name] = role;
            }

            graph = new RoleGraph
            {
                ByName = byName,
                Version = version,
                ExpiresAt = now + _options.PermissionCacheTtl,
            };
            _roleGraph = graph;
            return graph;
        }

        #endregion

        private static string BuildCacheKey(AuthSubject subject)
        {
            switch (subject.SubjectType)
            {
                case AuthSubjectType.Client:
                    return "c|" + subject.Id;
                case AuthSubjectType.Guest:
                    return "g|" + string.Join(",", subject.Roles);
                default:
                    subject.Claims.TryGetValue(AuthConstants.ClaimTypes.SecurityStamp, out string? stamp);
                    return "u|" + subject.Id + "|" + (stamp ?? string.Empty);
            }
        }

        private static double GetElapsedMilliseconds(long startTimestamp)
        {
            long elapsed = Stopwatch.GetTimestamp() - startTimestamp;
            return elapsed * 1000.0 / Stopwatch.Frequency;
        }
    }
}
