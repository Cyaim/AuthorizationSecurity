using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// 端点权限要求解析器：从端点元数据提取 [RequirePermission]/[AllowGuest]/[AllowAnonymous]，
    /// 结果按端点缓存，权限代码预解析为 <see cref="PermissionQuery"/>（热路径零解析）。
    /// </summary>
    public sealed class EndpointPermissionResolver
    {
        private readonly ConcurrentDictionary<Endpoint, EndpointRequirement?> _cache = new ConcurrentDictionary<Endpoint, EndpointRequirement?>();
        private readonly IOptions<CyaimAuthOptions> _options;
        private readonly ILogger<EndpointPermissionResolver> _logger;

        /// <summary>创建解析器</summary>
        public EndpointPermissionResolver(IOptions<CyaimAuthOptions> options, ILogger<EndpointPermissionResolver> logger)
        {
            _options = options;
            _logger = logger;
        }

        // 缓存键为 Endpoint 引用。正常应用端点集稳定；对会重建端点实例的宿主（热重载、
        // 运行期动态映射）设上限，超出即整体清空重建，避免无界增长。
        private const int MaxCacheEntries = 20_000;

        /// <summary>
        /// 获取端点的权限要求；null 表示不拦截。
        /// </summary>
        public EndpointRequirement? GetRequirement(Endpoint? endpoint)
        {
            if (endpoint == null)
            {
                // 未匹配任何端点（404），交给后续管道
                return null;
            }

            if (_cache.TryGetValue(endpoint, out EndpointRequirement? cached))
            {
                return cached;
            }

            if (_cache.Count >= MaxCacheEntries)
            {
                _logger.LogInformation("端点权限要求缓存超过上限 {Max}，整体清空重建", MaxCacheEntries);
                _cache.Clear();
            }

            return _cache.GetOrAdd(endpoint, BuildRequirement);
        }

        private EndpointRequirement? BuildRequirement(Endpoint endpoint)
        {
            // [AllowAnonymous] / [AllowGuest] 优先放行
            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() != null ||
                endpoint.Metadata.GetMetadata<AllowGuestAttribute>() != null)
            {
                return EndpointRequirement.Anonymous;
            }

            IReadOnlyList<RequirePermissionAttribute> attrs = endpoint.Metadata.GetOrderedMetadata<RequirePermissionAttribute>();
            if (attrs.Count == 0)
            {
                return _options.Value.ProtectAllEndpoints ? EndpointRequirement.AuthenticatedOnly : null;
            }

            var rules = new List<PermissionRule>(attrs.Count);
            foreach (RequirePermissionAttribute attr in attrs)
            {
                var queries = new List<PermissionQuery>(attr.PermissionCodes.Length);
                bool invalid = false;
                foreach (string code in attr.PermissionCodes)
                {
                    if (PermissionQuery.TryParse(code, out PermissionQuery query))
                    {
                        queries.Add(query);
                    }
                    else
                    {
                        // 配置错误按拒绝处理（fail-closed），并在日志中暴露
                        _logger.LogError("端点 {Endpoint} 的权限代码非法：\"{Code}\"，该端点将拒绝所有访问", endpoint.DisplayName, code);
                        invalid = true;
                    }
                }

                rules.Add(new PermissionRule(queries.ToArray(), attr.RequireAll, attr.Policy, invalid));
            }

            return new EndpointRequirement(rules.ToArray());
        }
    }

    /// <summary>
    /// 端点权限要求（不可变）。
    /// </summary>
    public sealed class EndpointRequirement
    {
        /// <summary>匿名放行</summary>
        public static readonly EndpointRequirement Anonymous = new EndpointRequirement(Array.Empty<PermissionRule>()) { AllowAnonymous = true };

        /// <summary>仅要求已认证</summary>
        public static readonly EndpointRequirement AuthenticatedOnly = new EndpointRequirement(Array.Empty<PermissionRule>());

        internal EndpointRequirement(PermissionRule[] rules)
        {
            Rules = rules;
        }

        /// <summary>是否匿名放行</summary>
        public bool AllowAnonymous { get; private set; }

        /// <summary>权限规则（全部满足才放行；空数组表示仅要求已认证）</summary>
        public PermissionRule[] Rules { get; }
    }

    /// <summary>
    /// 单条权限规则（对应一个 [RequirePermission] 特性）。
    /// </summary>
    public sealed class PermissionRule
    {
        internal PermissionRule(PermissionQuery[] queries, bool requireAll, string? policy, bool hasInvalidCode)
        {
            Queries = queries;
            RequireAll = requireAll;
            Policy = policy;
            HasInvalidCode = hasInvalidCode;
        }

        /// <summary>预解析的权限查询</summary>
        public PermissionQuery[] Queries { get; }

        /// <summary>true 全部满足；false 任一满足</summary>
        public bool RequireAll { get; }

        /// <summary>附加 ABAC 策略名</summary>
        public string? Policy { get; }

        /// <summary>存在非法权限代码（恒拒绝）</summary>
        public bool HasInvalidCode { get; }
    }
}
