using Cyaim.Authentication.Infrastructure.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Infrastructure
{
    /// <summary>
    /// 授权服务
    /// </summary>
    public class AuthenticationService : IAuthService
    {
        public readonly AuthOptions _authOptions;
        public readonly IMemoryCache _memoryCache;

        public readonly MemoryCacheEntryOptions cacheEntryOptions = new MemoryCacheEntryOptions()
             .SetPriority(CacheItemPriority.NeverRemove);

        public readonly Dictionary<string, bool> EndPoints = null;

        public AuthenticationService(AuthOptions authOptions, IMemoryCache memoryCache)
        {
            _authOptions = authOptions;
            _memoryCache = memoryCache;

            memoryCache.TryGetValue("Cyaim_AuthEndPoints", out EndPoints);
        }


        #region 鉴权
        /// <summary>
        /// 凭据鉴权
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public virtual async Task<bool> CheckAuthorization(HttpContext context)
        {
            string authKey = GetAuthorizationValue(context);

            //同步检测
            foreach (AccessSourceEnum item in _authOptions.AccessSources)
            {
                switch (item)
                {
                    case AccessSourceEnum.AuthCenter:
                        break;
                    case AccessSourceEnum.Cache:
                        {
                            var exr = await CheckAuthCache(context, authKey);
                            if (exr.IsPass)
                            {
                                continue;
                            }
                            return exr.IsAuth;
                        }
                    case AccessSourceEnum.Database:
                        {
                            var exr = await CheckAuthDatabase(context, authKey);
                            if (exr.IsPass)
                            {
                                Console.WriteLine();
                                Console.WriteLine($"节点  ->  {context.Request.Path}  因不在数据库权限监测范围,跳出数据库鉴权");
                                continue;
                            }
                            return exr.IsAuth;
                        }

                    case AccessSourceEnum.Default:
                        Console.WriteLine($"节点  ->  {context.Request.Path}  执行默认鉴权");
                        return CheckAuthDefault(context);
                }
            }

            return false;
        }

        /// <summary>
        /// 从缓存获取authKey的权限节点
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public async Task<(bool IsAuth, bool IsPass)> CheckAuthCache(HttpContext context, string authKey)
        {
            var handler = _authOptions?.ExtractCacheAuthEndPoints;

            AuthEndPointAttribute[] parm = null;
            if (handler != null)
            {
                parm = await handler?.Invoke(authKey, context, _authOptions);
            }

            bool isPass;
            if (parm == null)
            {
                isPass = true;
            }
            else
            {
                isPass = false;
            }
            return (CheckAuth(context, parm), isPass);
        }

        /// <summary>
        /// 从数据库获取authKey的权限节点
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authKey"></param>
        /// <returns></returns>
        public async Task<(bool IsAuth, bool IsPass)> CheckAuthDatabase(HttpContext context, string authKey)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            var handler = _authOptions?.ExtractDatabaseAuthEndPoints;
            AuthEndPointAttribute[] parm = null;
            if (handler != null)
            {
                parm = await handler?.Invoke(authKey, context, _authOptions);
            }
            stopwatch.Stop();
            Console.WriteLine("数据库鉴权耗时ms：" + stopwatch.Elapsed.TotalMilliseconds);

            bool isPass;
            if (parm == null)
            {
                isPass = true;
            }
            else
            {
                isPass = false;
            }
            Stopwatch methodWatch = new Stopwatch();
            methodWatch.Start();
            (bool IsAuth, bool IsPass) r = (CheckAuth(context, parm), isPass);
            methodWatch.Stop();
            Console.WriteLine("通用鉴权耗时ms：" + methodWatch.Elapsed.TotalMilliseconds);

            return r;
        }

        /// <summary>
        /// 默认鉴权
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public bool CheckAuthDefault(HttpContext context)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();
            bool isAccess = CheckAuth(context, _authOptions.WatchAuthEndPoint);
            stopwatch.Stop();
            Console.WriteLine("默认鉴权耗时ms:" + stopwatch.ElapsedMilliseconds);

            return isAccess;
        }

        /// <summary>
        /// 通用鉴权方法
        /// </summary>
        /// <param name="context"></param>
        /// <param name="authEndPoints">授权节点列表</param>
        /// <returns></returns>
        public bool CheckAuth(HttpContext context, AuthEndPointAttribute[] authEndPoints)
        {

            if (authEndPoints == null || authEndPoints.Length < 1)
            {
                return false;
            }

            #region MyRegion
            //string controllerName = context.GetRouteValue("controller")?.ToString().ToLower();
            //string actionName = context.GetRouteValue("action")?.ToString().ToLower();
            //string method = context.Request?.Method?.ToUpper();
            //if (string.IsNullOrEmpty(method))
            //{
            //    return false;
            //}
            //if (string.IsNullOrEmpty(controllerName) || string.IsNullOrEmpty(actionName))
            //{
            //    //    var reqPaths = context.Request.Path.Value.Split('/').TakeLast(2).ToArray();
            //    //    if (reqPaths.Length < 2)
            //    //    {
            //    //不在监听范围
            //    return true;
            //    //    }
            //    //    controllerName = reqPaths[0];
            //    //    actionName = reqPaths[1];
            //}

            ////搜索节点，路由标记不为空、Http请求方法符合标记的请求方法
            //var matcheps = authEndPointParms.Where(x => x.Routes != null && x.Routes.Any(y => y.HttpMethods.Any(z => z?.ToUpper() == method)));
            ////搜索节点，忽略Controller大小写、Action匹配小写
            //var allowep = matcheps.FirstOrDefault(x => x.ControllerName.IndexOf(controllerName, StringComparison.CurrentCultureIgnoreCase) == 0 && x.ActionName?.ToLower() == actionName);

            ////允许访问
            //var isAllow = allowep.AuthEndPointAttributes?.FirstOrDefault()?.IsAllow;
            //if (isAllow.HasValue && isAllow.Value)
            //{
            //    return true;
            //}

            ////当被访问的Action没有标记授权节点时，查找Controller授权节点
            //if (allowep.AuthEndPointAttributes != null && allowep.AuthEndPointAttributes.Length == 0)
            //{
            //    var allowAll = authEndPointParms.FirstOrDefault(x => x.ActionName == "*");
            //    var isAllowAll = allowAll.AuthEndPointAttributes.FirstOrDefault()?.IsAllow;

            //    if (isAllowAll.HasValue && isAllowAll.Value)
            //    {
            //        return true;
            //    }
            //}
            #endregion


            string controllerName = context.GetRouteValue(AuthOptions.CONTROLLER)?.ToString().ToLower();
            string actionName = context.GetRouteValue(AuthOptions.ACTION)?.ToString().ToLower();
            string method = context.Request?.Method?.ToUpper();
            if (string.IsNullOrEmpty(method))
            {
                return false;
            }
            if (string.IsNullOrEmpty(controllerName) || string.IsNullOrEmpty(actionName))
            {
                //    var reqPaths = context.Request.Path.Value.Split('/').TakeLast(2).ToArray();
                //    if (reqPaths.Length < 2)
                //    {
                //不在监听范围
                return true;
                //    }
                //    controllerName = reqPaths[0];
                //    actionName = reqPaths[1];
            }

            //搜索节点，路由标记不为空、Http请求方法符合标记的请求方法
            var matcheps = authEndPoints.Where(x => x.Routes != null && x.Routes.Any(y => y.HttpMethods.Any(z => z?.ToUpper() == method)));
            //搜索节点，忽略Controller大小写、Action匹配小写
            var allowep = matcheps.FirstOrDefault(x =>
            x.ControllerName.IndexOf(controllerName, StringComparison.CurrentCultureIgnoreCase) == 0 &&
            x.ActionName?.ToLower() == actionName);


            ////搜索节点，忽略Controller大小写、Action匹配小写
            //var alloweps = matcheps.Where(x =>
            //x.ControllerName.IndexOf(controllerName, StringComparison.CurrentCultureIgnoreCase) == 0);

            ////通过MVC找到的Controller和Action，查找监听节点，通过节点找到实际路由模版
            ////var watchep = _authOptions.WatchAuthEndPoint.FirstOrDefault(x => x.ControllerName?.ToLower() == controllerName.ToLower() + "controller"
            ////&& x.ActionName?.ToLower() == actionName);
            ////var allowep = alloweps.FirstOrDefault(x => watchep.Routes.Any(y => y.Template?.ToLower() == x.ActionName?.ToLower()));

            //允许访问
            bool? isAllow = allowep?.IsAllow;
            bool? allowGuest = allowep?.AllowGuest;
            if ((allowGuest.HasValue && allowGuest.Value) || (isAllow.HasValue && isAllow.Value))
            {
                return true;
            }

            //当被访问的Action没有标记授权节点时，查找Controller授权节点
            if (allowep == null)
            {
                var allowAll = authEndPoints.FirstOrDefault(x => x.ControllerName?.ToLower() == controllerName.ToLower() + AuthOptions.CONTROLLER && x.ActionName == "*");
                var isAllowAll = allowAll?.IsAllow;
                var allowGuestAll = allowAll?.AllowGuest;

                if ((allowGuestAll.HasValue && allowGuestAll.Value) || (isAllowAll.HasValue && isAllowAll.Value))
                {
                    return true;
                }
            }

            return false;
        }

        #endregion

        #region 默认获取权限节点方法

        ///// <summary>
        ///// 从缓存获取权限节点
        ///// </summary>
        ///// <returns></returns>
        //public static AuthEndPointAttribute[] DefaultExtractCacheAuthEndPoints()
        //{
        //    return null;
        //}

        ///// <summary>
        ///// 从数据库获取权限节点
        ///// </summary>
        ///// <returns></returns>
        //public static AuthEndPointAttribute[] DefaultExtractDatabaseAuthEndPoints()
        //{
        //    return null;
        //}
        #endregion

        #region 获取Token

        /// <summary>
        /// Get credential by querystring
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthQuery(HttpContext context, string key)
        {
            context.Request.Query.TryGetValue(key, out StringValues vs);
            var token = vs.ToString();

            return token;
        }

        /// <summary>
        /// Get credential by request header
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthHeader(HttpContext context, string key)
        {
            context.Request.Headers.TryGetValue(key, out StringValues vs);
            var token = vs.ToString();

            return token;
        }

        /// <summary>
        /// Get credential by cookie
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public virtual string GetAuthCookie(HttpContext context, string key)
        {
            context.Request.Cookies.TryGetValue(key, out string token);

            return token;
        }
        #endregion

        #region 辅助方法
        /// <summary>
        /// 获取授权Key
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public string GetAuthorizationValue(HttpContext context)
        {
            var key = _authOptions.SourceKey;
            string authKey;

            // 搜索凭据位置
            switch (_authOptions.SourceLocation)
            {
                case Microsoft.OpenApi.Models.ParameterLocation.Query:
                    authKey = GetAuthQuery(context, key);
                    break;
                case Microsoft.OpenApi.Models.ParameterLocation.Header:
                    authKey = GetAuthHeader(context, key);
                    break;
                case Microsoft.OpenApi.Models.ParameterLocation.Path:
                    throw new NotSupportedException("不支持从“Path”搜索凭据");
                case Microsoft.OpenApi.Models.ParameterLocation.Cookie:
                    authKey = GetAuthCookie(context, key);
                    break;
                default:
                    throw new NotSupportedException("不支持从该位置搜索凭据");
            }

            return authKey;
        }

        /// <summary>
        /// 缓存注册权限节点
        /// </summary>
        /// <param name="accessCode"></param>
        /// <param name="isAccept"></param>
        public void RegisterAccessCode(string accessCode, bool isAccept)
        {
            var accs = _memoryCache.GetOrCreate<Dictionary<string, bool>>("Cyaim_AuthEndPoints", x => new Dictionary<string, bool>());

            accs.TryAdd(accessCode, isAccept);

            _memoryCache.Set("authEndPoints", accs, cacheEntryOptions);
        }

        #endregion

    }
}
