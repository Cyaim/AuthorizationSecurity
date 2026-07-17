using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Core
{
    /// <summary>
    /// 核心引擎配置。
    /// </summary>
    public class CyaimAuthCoreOptions
    {
        /// <summary>令牌签发者（iss），默认 "cyaim-auth"</summary>
        public string Issuer { get; set; } = "cyaim-auth";

        /// <summary>令牌受众（aud），默认 "cyaim-api"</summary>
        public string Audience { get; set; } = "cyaim-api";

        /// <summary>
        /// HMAC 签名密钥（HS256，至少 32 字节 UTF-8）。
        /// 与 <see cref="RsaKeyFilePath"/> 均未配置时自动生成并持久化 RSA 开发密钥。
        /// </summary>
        public string? HmacSigningKey { get; set; }

        /// <summary>
        /// RSA 密钥持久化路径（RS256）。文件不存在时自动生成 2048 位密钥并写入。
        /// </summary>
        public string? RsaKeyFilePath { get; set; }

        /// <summary>默认访问令牌有效期，默认 1 小时</summary>
        public TimeSpan DefaultAccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>默认刷新令牌有效期，默认 14 天</summary>
        public TimeSpan DefaultRefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

        /// <summary>校验令牌时的时钟偏移容忍，默认 30 秒</summary>
        public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>游客主体拥有的角色（未认证请求以这些角色评估权限）</summary>
        public List<string> GuestRoles { get; set; } = new List<string>();

        /// <summary>
        /// 编译权限集缓存TTL（版本号失效之外的兜底），默认 5 分钟。
        /// 使用无法递增版本号的外部存储时依赖此值感知权限变更。
        /// </summary>
        public TimeSpan PermissionCacheTtl { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>权限集缓存最大主体数，超出后整体清空重建，默认 10000</summary>
        public int MaxCachedPermissionSets { get; set; } = 10_000;

        /// <summary>签发用户令牌时是否携带 perm 权限声明（离线鉴权），默认 true</summary>
        public bool IncludePermissionsInToken { get; set; } = true;

        /// <summary>审计事件内存保留条数，默认 5000</summary>
        public int AuditCapacity { get; set; } = 5000;

        /// <summary>审计 JSONL 文件路径（空则不落盘）</summary>
        public string? AuditFilePath { get; set; }

        /// <summary>登录失败锁定阈值，默认 5 次</summary>
        public int MaxAccessFailedCount { get; set; } = 5;

        /// <summary>登录失败锁定时长，默认 5 分钟</summary>
        public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(5);
    }
}
