using System;

namespace Cyaim.Authentication.Abstractions.Services
{
    /// <summary>
    /// 时钟抽象（令牌有效期、锁定判断等依赖当前时间的逻辑可测试化）。
    /// </summary>
    public interface IAuthClock
    {
        /// <summary>当前UTC时间</summary>
        DateTimeOffset UtcNow { get; }
    }
}
