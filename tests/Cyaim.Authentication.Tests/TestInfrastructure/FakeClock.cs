using System;
using Cyaim.Authentication.Abstractions.Services;

namespace Cyaim.Authentication.Tests.TestInfrastructure
{
    /// <summary>
    /// 可控测试时钟：可直接设置或推进当前时间。
    /// </summary>
    public sealed class FakeClock : IAuthClock
    {
        /// <summary>当前UTC时间（可设置）</summary>
        public DateTimeOffset UtcNow { get; set; }

        /// <summary>创建时钟，默认从固定时间 2026-01-01T00:00:00Z 开始</summary>
        public FakeClock()
            : this(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
        {
        }

        /// <summary>创建时钟并指定初始时间</summary>
        public FakeClock(DateTimeOffset initial)
        {
            UtcNow = initial;
        }

        /// <summary>推进时间</summary>
        public void Advance(TimeSpan delta)
        {
            UtcNow += delta;
        }
    }
}
