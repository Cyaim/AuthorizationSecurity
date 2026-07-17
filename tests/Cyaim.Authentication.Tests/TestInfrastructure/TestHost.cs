using System;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;
using Microsoft.Extensions.DependencyInjection;

namespace Cyaim.Authentication.Tests.TestInfrastructure
{
    /// <summary>
    /// 用真实 DI 容器组装核心服务（AddCyaimAuthCore + AddInMemoryStore），少 mock 多真实对象。
    /// </summary>
    public static class TestHost
    {
        /// <summary>
        /// 构建带内存存储的服务容器。<paramref name="clock"/> 会替换默认系统时钟。
        /// </summary>
        public static ServiceProvider Build(
            FakeClock clock,
            Action<CyaimAuthCoreOptions>? configure = null,
            Action<CyaimAuthCoreBuilder>? builder = null)
        {
            var services = new ServiceCollection();
            // 先注册测试时钟：AddCyaimAuthCore 内部使用 TryAddSingleton，不会覆盖
            services.AddSingleton<IAuthClock>(clock);
            CyaimAuthCoreBuilder coreBuilder = services.AddCyaimAuthCore(configure).AddInMemoryStore();
            builder?.Invoke(coreBuilder);
            return services.BuildServiceProvider();
        }
    }
}
