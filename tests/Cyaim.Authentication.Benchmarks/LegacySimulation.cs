using System;
using System.Linq;

namespace Cyaim.Authentication.Benchmarks
{
    /// <summary>
    /// 模拟 1.x 路由记录（等价于旧版 HttpRouteAttribute 的 HttpMethods/Template 形态）。
    /// </summary>
    public sealed class LegacyRouteEntry
    {
        /// <summary>允许的 HTTP 方法</summary>
        public string?[] HttpMethods { get; set; } = Array.Empty<string?>();

        /// <summary>路由模板</summary>
        public string? Template { get; set; }
    }

    /// <summary>
    /// 模拟 1.x 端点权限记录（等价于旧版 AuthEndPointAttribute 的 ControllerName/ActionName/Routes 形态）。
    /// </summary>
    public sealed class LegacyAuthEndPoint
    {
        /// <summary>控制器名（含 Controller 后缀）</summary>
        public string ControllerName { get; set; } = string.Empty;

        /// <summary>操作名</summary>
        public string? ActionName { get; set; }

        /// <summary>路由记录</summary>
        public LegacyRouteEntry[]? Routes { get; set; }

        /// <summary>是否允许访问</summary>
        public bool IsAllow { get; set; }

        /// <summary>是否允许游客访问</summary>
        public bool AllowGuest { get; set; }
    }

    /// <summary>
    /// 复刻旧版 AuthenticationService.CheckAuth 的查找形态：
    /// LINQ Where + FirstOrDefault + 每次比较 ToLower/ToUpper 分配字符串。
    /// 仅用于基准对比，不引用已过时 API。
    /// </summary>
    public static class LegacyAuthChecker
    {
        /// <summary>
        /// 与旧版 CheckAuth 相同形态的端点权限判断。
        /// </summary>
        /// <param name="authEndPoints">全部端点权限记录</param>
        /// <param name="controllerName">路由控制器名（已小写、不含 Controller 后缀）</param>
        /// <param name="actionName">路由操作名（已小写）</param>
        /// <param name="method">HTTP 方法（大写）</param>
        public static bool CheckAuth(LegacyAuthEndPoint[] authEndPoints, string controllerName, string actionName, string method)
        {
            if (authEndPoints == null || authEndPoints.Length < 1)
            {
                return false;
            }

            // 搜索节点，路由标记不为空、Http请求方法符合标记的请求方法（与旧实现一致）
            var matchEndPoints = authEndPoints.Where(x => x.Routes != null && x.Routes.Any(y => y.HttpMethods.Any(z => z?.ToUpper() == method)));
            // 搜索节点，忽略Controller大小写、Action匹配小写（与旧实现一致）
            var allowEndPoint = matchEndPoints.FirstOrDefault(x => x.ControllerName.IndexOf(controllerName, StringComparison.CurrentCultureIgnoreCase) == 0 && x.ActionName?.ToLower() == actionName);

            bool? isAllow = allowEndPoint?.IsAllow;
            bool? allowGuest = allowEndPoint?.AllowGuest;
            if ((allowGuest.HasValue && allowGuest.Value) || (isAllow.HasValue && isAllow.Value))
            {
                return true;
            }

            // 当被访问的Action没有标记授权节点时，查找Controller授权节点（与旧实现一致）
            if (allowEndPoint == null)
            {
                var allowAll = authEndPoints.FirstOrDefault(x => x.ControllerName?.ToLower() == controllerName.ToLower() + "controller" && x.ActionName == "*");
                bool? isAllowAll = allowAll?.IsAllow;
                bool? allowGuestAll = allowAll?.AllowGuest;

                if ((allowGuestAll.HasValue && allowGuestAll.Value) || (isAllowAll.HasValue && isAllowAll.Value))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
