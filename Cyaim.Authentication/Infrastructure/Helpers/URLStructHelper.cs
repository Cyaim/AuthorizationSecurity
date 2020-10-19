using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.Infrastructure.Helpers
{
    public class URLStructHelper
    {
        /// <summary>
        /// URL结构
        /// </summary>
        public struct URLStruct
        {
            /// <summary>
            /// 协议
            /// </summary>
            public string Scheme { get; set; }

            /// <summary>
            /// 主机
            /// </summary>
            public string Host { get; set; }

            /// <summary>
            /// 请求路径
            /// </summary>
            public string Path { get; set; }

            /// <summary>
            /// 控制器名称
            /// </summary>
            public string Controller { get; set; }

            /// <summary>
            /// 方法
            /// </summary>
            public string Action { get; set; }

            /// <summary>
            /// 请求参数
            /// </summary>
            public string QueryString { get; set; }


            public const string MARK_CONTROLLER = "{controller}";
            public const string MARK_ACTION = "{action}";
            public static readonly int MarkControllerLength = MARK_CONTROLLER.Length;
            public static readonly int MarkActionLength = MARK_ACTION.Length;

            public const string MARK_SCHEME = ":/";
            public const char MARK_PATHSPLIT = '/';
            public const char MARK_QUERYSPLIT = '?';
        }

        /// <summary>
        /// 获取URL结构
        /// </summary>
        /// <param name="template">路由模版，"/api/v1/{controller}/{action}"</param>
        /// <param name="url"></param>
        /// <returns></returns>
        public static URLStruct GetUrlStruct(string template, string url)
        {
            URLStruct urls = new URLStruct();

            //url = @"https://localhost:5001/api/v1/weatherforecast";
            //url = @"https://localhost:5001/api/v1/weatherforecast/sdfasd";
            //url = @"https://localhost:5001/api/v1/weatherforecast/sdfasd?path=https://www.baidu.com";
            //url = @"localhost:5001/api/v1/weatherforecast/sdfasd?path=https://www.baidu.com";

            //1、模版路径前缀
            //2、模版中{controller}起始位置、结束字符
            //3、{action}起始位置、结束字符
            int tempControllerIndex = template.IndexOf(URLStruct.MARK_CONTROLLER);
            //URI前缀
            //string pathPreStr = template.Substring(0, templateLength - tempControllerIndex - URLStruct.MarkControllerLength - 1);

            //从0到{controller}标记位置
            string pathPreStr = template.Substring(0, tempControllerIndex);

            //协议标记位置必须在模版前缀之前
            int schemeIndex = url.LastIndexOf(URLStruct.MARK_SCHEME, tempControllerIndex);
            if (schemeIndex != -1)
            {
                for (int currIndex = 0; currIndex - schemeIndex < 2; schemeIndex = currIndex - schemeIndex < 2 ? currIndex : schemeIndex)
                {
                    currIndex = url.IndexOf(URLStruct.MARK_PATHSPLIT, schemeIndex + 1);
                }

                urls.Scheme = url.Substring(0, ++schemeIndex);
            }

            //主机地址，无协议头直接从0取，有协议头从协议头位置到模版路径前缀位置
            int controllerIndex = url.IndexOf(pathPreStr, 0);
            if (schemeIndex == -1)
            {
                urls.Host = url.Substring(0, controllerIndex);
            }
            else
            {
                controllerIndex = url.IndexOf(URLStruct.MARK_PATHSPLIT, schemeIndex);
                urls.Host = url.Substring(schemeIndex, controllerIndex - schemeIndex);
            }


            int queryIndex = url.IndexOf(URLStruct.MARK_QUERYSPLIT, controllerIndex);
            if (queryIndex == -1)
            {
                urls.Path = url.Substring(controllerIndex, url.Length - controllerIndex);
            }
            else
            {
                urls.Path = url.Substring(controllerIndex, queryIndex - controllerIndex);
                urls.QueryString = url.Substring(queryIndex, url.Length - queryIndex);
            }



            url = urls.Path.Replace(pathPreStr, string.Empty);
            string[] paths = url.Split(URLStruct.MARK_PATHSPLIT);
            urls.Controller = paths.Length > 0 ? paths[0] : null;
            urls.Action = paths.Length > 1 ? paths[1] : null;

            return urls;
        }

    }
}
