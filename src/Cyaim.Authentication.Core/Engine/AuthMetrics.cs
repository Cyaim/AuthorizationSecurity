using System.Collections.Generic;
using System.Diagnostics.Metrics;

namespace Cyaim.Authentication.Core.Engine
{
    /// <summary>
    /// 框架指标（System.Diagnostics.Metrics，可接 OpenTelemetry / dotnet-counters）。
    /// Meter 名称：<c>Cyaim.Authentication</c>。
    /// </summary>
    public static class AuthMetrics
    {
        /// <summary>Meter 名称</summary>
        public const string MeterName = "Cyaim.Authentication";

        private static readonly Meter Meter = new Meter(MeterName, "2.0.0");

        private static readonly Counter<long> Checks =
            Meter.CreateCounter<long>("cyaim_auth.permission_checks", "count", "权限检查总数");

        private static readonly Counter<long> Denials =
            Meter.CreateCounter<long>("cyaim_auth.permission_denials", "count", "权限拒绝总数");

        private static readonly Counter<long> CacheHits =
            Meter.CreateCounter<long>("cyaim_auth.permission_set_cache_hits", "count", "权限集缓存命中数");

        private static readonly Counter<long> CacheMisses =
            Meter.CreateCounter<long>("cyaim_auth.permission_set_cache_misses", "count", "权限集缓存未命中数");

        private static readonly Histogram<double> CheckDuration =
            Meter.CreateHistogram<double>("cyaim_auth.check_duration", "ms", "单次权限判断耗时");

        private static readonly Counter<long> TokensIssued =
            Meter.CreateCounter<long>("cyaim_auth.tokens_issued", "count", "签发令牌总数");

        /// <summary>记录一次权限检查</summary>
        public static void RecordCheck(bool granted, bool cacheHit, double elapsedMs)
        {
            Checks.Add(1);
            if (!granted)
            {
                Denials.Add(1);
            }
            if (cacheHit)
            {
                CacheHits.Add(1);
            }
            else
            {
                CacheMisses.Add(1);
            }
            CheckDuration.Record(elapsedMs);
        }

        /// <summary>记录一次令牌签发</summary>
        public static void RecordTokenIssued(string grantOrKind)
        {
            TokensIssued.Add(1, new KeyValuePair<string, object?>("kind", grantOrKind));
        }
    }
}
