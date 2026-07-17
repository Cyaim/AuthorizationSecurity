using Microsoft.Extensions.Logging;

namespace Cyaim.Authentication.Core
{
    /// <summary>
    /// 框架日志事件Id（结构化日志过滤用）。
    /// </summary>
    public static class AuthLogEvents
    {
        /// <summary>权限拒绝</summary>
        public static readonly EventId PermissionDenied = new EventId(2001, nameof(PermissionDenied));
        /// <summary>权限集编译完成</summary>
        public static readonly EventId PermissionSetBuilt = new EventId(2002, nameof(PermissionSetBuilt));
        /// <summary>权限集缓存整体清空</summary>
        public static readonly EventId CacheReset = new EventId(2003, nameof(CacheReset));
        /// <summary>策略不存在</summary>
        public static readonly EventId PolicyNotFound = new EventId(2004, nameof(PolicyNotFound));
        /// <summary>策略评估异常</summary>
        public static readonly EventId PolicyError = new EventId(2005, nameof(PolicyError));
        /// <summary>令牌签发</summary>
        public static readonly EventId TokenIssued = new EventId(2101, nameof(TokenIssued));
        /// <summary>令牌校验失败</summary>
        public static readonly EventId TokenValidationFailed = new EventId(2102, nameof(TokenValidationFailed));
        /// <summary>检测到刷新令牌重放，家族已吊销</summary>
        public static readonly EventId RefreshTokenReplay = new EventId(2103, nameof(RefreshTokenReplay));
        /// <summary>生成开发签名密钥</summary>
        public static readonly EventId DevSigningKeyGenerated = new EventId(2104, nameof(DevSigningKeyGenerated));
        /// <summary>登录成功</summary>
        public static readonly EventId LoginSucceeded = new EventId(2201, nameof(LoginSucceeded));
        /// <summary>登录失败</summary>
        public static readonly EventId LoginFailed = new EventId(2202, nameof(LoginFailed));
        /// <summary>账户锁定</summary>
        public static readonly EventId AccountLockedOut = new EventId(2203, nameof(AccountLockedOut));
        /// <summary>端点权限扫描完成</summary>
        public static readonly EventId EndpointsScanned = new EventId(2301, nameof(EndpointsScanned));
        /// <summary>请求被中间件拒绝</summary>
        public static readonly EventId RequestDenied = new EventId(2302, nameof(RequestDenied));
    }
}
