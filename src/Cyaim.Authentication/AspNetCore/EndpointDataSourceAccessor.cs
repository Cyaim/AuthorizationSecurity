using System.Collections.Generic;
using Microsoft.AspNetCore.Routing;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// 端点数据源持有器：UseCyaimAuthentication 时从宿主的 IEndpointRouteBuilder 捕获，
    /// 供启动后端点权限扫描使用（跨宿主形态可靠，不依赖 DI 中是否注册 EndpointDataSource）。
    /// </summary>
    public sealed class EndpointDataSourceAccessor
    {
        /// <summary>宿主的端点数据源集合（应用启动完成后可安全枚举）</summary>
        public ICollection<EndpointDataSource>? Sources { get; set; }
    }
}
