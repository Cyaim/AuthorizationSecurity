using System;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 授权数据版本：用户/角色/权限任何影响鉴权结果的变更都应递增版本，
    /// 评估器据此使缓存的编译权限集失效。
    /// </summary>
    public interface IAuthStoreVersion
    {
        /// <summary>当前版本号（单调递增）</summary>
        long Version { get; }

        /// <summary>递增版本（存储变更后调用）</summary>
        void Bump();

        /// <summary>版本变更通知</summary>
        event Action<long>? Changed;
    }
}
