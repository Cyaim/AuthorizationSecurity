using Cyaim.Authentication.Infrastructure.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using static Cyaim.Authentication.Infrastructure.AuthenticationService;

namespace Cyaim.Authentication.Infrastructure
{
    public class AuthOptions
    {
        /// <summary>
        /// 权限检测序列，授权中心、数据库、缓存、特性
        /// </summary>
        public AccessSourceEnum[] AccessSources { get; } = { AccessSourceEnum.AuthCenter, AccessSourceEnum.Cache, AccessSourceEnum.Database, AccessSourceEnum.Default };

        /// <summary>
        /// 访问凭据Key
        /// </summary>
        public string SourceKey { get; set; } = "Authorization";

        /// <summary>
        /// 访问权限代码前缀
        /// </summary>
        public string PreAccessEndPointKey { get; set; }

        /// <summary>
        /// Http凭据位置，默认从Header提取
        /// </summary>
        public ParameterLocation SourceLocation { get; set; } = ParameterLocation.Header;

        /// <summary>
        /// 监听程序集路径
        /// </summary>
        public string WatchAssemblyPath { get; set; }

        /// <summary>
        /// 监听的授权节点
        /// </summary>
        //public AuthEndPointParm[] WatchAuthEndPoint { get; set; }
        public AuthEndPointAttribute[] WatchAuthEndPoint { get; set; }

        /// <summary>
        /// 未授权响应配置
        /// </summary>
        public NonAccessParm NonAccessParm { get; set; }

        /// <summary>
        /// 提取授权节点
        /// </summary>
        /// <param name="authKey">请求凭据</param>
        /// <param name="httpContext">HTTP上下文</param>
        /// <param name="authOptions">授权配置</param>
        /// <returns></returns>
        public delegate Task<AuthEndPointAttribute[]> ExtractAuthEndPointsHandler(string authKey, HttpContext httpContext, AuthOptions authOptions);

        /// <summary>
        /// 从缓存提取
        /// </summary>
        public ExtractAuthEndPointsHandler ExtractCacheAuthEndPoints { get; set; } /*= new ExtractAuthEndPointsHandler(DefaultExtractCacheAuthEndPoints);*/

        /// <summary>
        /// 从数据库提取
        /// </summary>
        public ExtractAuthEndPointsHandler ExtractDatabaseAuthEndPoints { get; set; } /*= new ExtractAuthEndPointsHandler(DefaultExtractDatabaseAuthEndPoints);*/

        public const string CONTROLLER = "controller";
        public const string ACTION = "action";
    }

    /// <summary>
    /// 权限节点访问处理方法
    /// </summary>
    public enum AccessSourceEnum
    {
        /// <summary>
        /// 授权中心
        /// </summary>
        AuthCenter,
        /// <summary>
        /// 缓存
        /// </summary>
        Cache,
        /// <summary>
        /// 数据库
        /// </summary>
        Database,
        /// <summary>
        /// 默认权限，程序集标记特性
        /// </summary>
        Default
    }

    /// <summary>
    /// 未授权响应参数
    /// </summary>
    public class NonAccessParm
    {
        /// <summary>
        /// 无权限HTTP响应状态码
        /// </summary>
        public int NonAccessResponseStatus { get; set; } = 403;

        /// <summary>
        /// 无权限HTTP响应类型
        /// </summary>
        public string NonAccessResponseContentType { get; set; } = "application/json";

        /// <summary>
        /// 无权限响应内容
        /// </summary>
        public string NonAccessResponseContent { get; set; }
    }


    /// <summary>
    /// HTTP 方法
    /// </summary>
    public static class HttpMethod
    {

        /// <summary>
        /// HTTP 请求方法映射
        /// </summary>
        public static readonly Dictionary<string, int> HttpMethodMaps = new Dictionary<string, int>()
        {
            { "GET",(int)HttpMethodEnum.GET},
            { "POST",(int)HttpMethodEnum.POST},
            { "DELETE",(int)HttpMethodEnum.DELETE},
            { "PUT",(int)HttpMethodEnum.PUT},
            { "PATCH",(int)HttpMethodEnum.PATCH},
            { "HEAD",(int)HttpMethodEnum.HEAD},
            { "CONNECT",(int)HttpMethodEnum.CONNECT},
            { "TRACE",(int)HttpMethodEnum.TRACE},
            { "OPTIONS",(int)HttpMethodEnum.OPTIONS},
        };

        /// <summary>
        /// HTTP 请求方法枚举
        /// </summary>
        public enum HttpMethodEnum
        {
            GET = 2,
            POST = 4,
            DELETE = 8,
            PUT = 16,
            PATCH = 32,
            HEAD = 64,
            CONNECT = 128,
            TRACE = 256,
            OPTIONS = 512,
        }
    }
}
