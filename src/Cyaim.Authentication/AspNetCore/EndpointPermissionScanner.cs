using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// 应用启动完成后扫描全部端点的权限标注，登记到权限定义存储（管理面板据此展示可分配权限）。
    /// </summary>
    public sealed class EndpointPermissionScanner : IHostedService
    {
        private readonly IServiceProvider _services;
        private readonly IHostApplicationLifetime _lifetime;
        private readonly IOptions<CyaimAuthOptions> _options;
        private readonly ILogger<EndpointPermissionScanner> _logger;

        /// <summary>创建扫描器</summary>
        public EndpointPermissionScanner(
            IServiceProvider services,
            IHostApplicationLifetime lifetime,
            IOptions<CyaimAuthOptions> options,
            ILogger<EndpointPermissionScanner> logger)
        {
            _services = services;
            _lifetime = lifetime;
            _options = options;
            _logger = logger;
        }

        /// <inheritdoc/>
        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!_options.Value.ScanEndpointPermissions)
            {
                return Task.CompletedTask;
            }

            // 等应用完全启动（端点数据源已定型）再扫描
            _lifetime.ApplicationStarted.Register(() =>
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await ScanAsync(CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "端点权限扫描失败");
                    }
                });
            });

            return Task.CompletedTask;
        }

        private async Task ScanAsync(CancellationToken cancellationToken)
        {
            var sources = new List<EndpointDataSource>();

            // 首选：UseCyaimAuthentication 捕获的宿主数据源
            EndpointDataSourceAccessor? accessor = _services.GetService<EndpointDataSourceAccessor>();
            if (accessor?.Sources != null)
            {
                sources.AddRange(accessor.Sources);
            }

            // 兜底：DI 中的数据源
            EndpointDataSource? composite = _services.GetService<EndpointDataSource>();
            if (composite != null)
            {
                sources.Add(composite);
            }
            sources.AddRange(_services.GetServices<EndpointDataSource>());

            var codes = new Dictionary<string, PermissionDefinition>(StringComparer.OrdinalIgnoreCase);
            var seenEndpoints = new HashSet<Endpoint>();

            foreach (EndpointDataSource source in sources)
            {
                foreach (Endpoint endpoint in source.Endpoints)
                {
                    if (!seenEndpoints.Add(endpoint))
                    {
                        continue;
                    }

                    foreach (RequirePermissionAttribute attr in endpoint.Metadata.GetOrderedMetadata<RequirePermissionAttribute>())
                    {
                        foreach (string code in attr.PermissionCodes)
                        {
                            if (!PermissionCode.TryNormalize(code, out string normalized))
                            {
                                _logger.LogWarning("端点 {Endpoint} 的权限代码非法：\"{Code}\"", endpoint.DisplayName, code);
                                continue;
                            }

                            if (!codes.ContainsKey(normalized))
                            {
                                string[] segments = PermissionCode.Split(normalized);
                                codes[normalized] = new PermissionDefinition
                                {
                                    Code = normalized,
                                    DisplayName = normalized,
                                    Group = segments.Length > 1 ? segments[0] : null,
                                    Description = $"端点：{endpoint.DisplayName}",
                                    Origin = PermissionOrigin.EndpointDiscovery,
                                };
                            }
                        }
                    }
                }
            }

            var store = _services.GetService<IPermissionDefinitionStore>();
            if (store != null && codes.Count > 0)
            {
                await store.UpsertAsync(codes.Values, cancellationToken);
            }

            _logger.LogInformation(AuthLogEvents.EndpointsScanned,
                "端点权限扫描完成，共发现 {Count} 个权限代码{Persisted}",
                codes.Count, store != null && codes.Count > 0 ? "，已登记到权限定义存储" : "");
        }

        /// <inheritdoc/>
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
