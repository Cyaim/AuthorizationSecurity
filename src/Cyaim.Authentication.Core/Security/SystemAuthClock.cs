using System;
using Cyaim.Authentication.Abstractions.Services;

namespace Cyaim.Authentication.Core.Security
{
    /// <summary>
    /// 系统时钟。
    /// </summary>
    public sealed class SystemAuthClock : IAuthClock
    {
        /// <inheritdoc/>
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
}
