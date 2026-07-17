using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 端点公共 HTTP 辅助：JSON 响应、OAuth 错误、作用域解析、返回地址校验。
    /// </summary>
    internal static class ServerHttp
    {
        /// <summary>序列化配置（不写 null 属性）</summary>
        internal static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        /// <summary>
        /// 写 JSON 响应。
        /// </summary>
        public static async Task WriteJsonAsync(HttpContext context, int statusCode, object payload)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "application/json; charset=utf-8";
            await JsonSerializer.SerializeAsync(context.Response.Body, payload, payload.GetType(), JsonOptions, context.RequestAborted).ConfigureAwait(false);
        }

        /// <summary>
        /// 写 OAuth 2.0 错误响应（RFC 6749 §5.2）。含 Cache-Control:no-store / Pragma:no-cache。
        /// </summary>
        public static Task WriteOAuthErrorAsync(HttpContext context, int statusCode, string error, string? errorDescription = null)
        {
            var payload = new Dictionary<string, object?>
            {
                ["error"] = error,
            };
            if (!string.IsNullOrEmpty(errorDescription))
            {
                payload["error_description"] = errorDescription;
            }
            // RFC 6749 §5.2：错误响应也不得被缓存
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.Headers["Pragma"] = "no-cache";
            return WriteJsonAsync(context, statusCode, payload);
        }

        /// <summary>
        /// 写 HTML 响应。
        /// </summary>
        public static async Task WriteHtmlAsync(HttpContext context, int statusCode, string html)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(html, context.RequestAborted).ConfigureAwait(false);
        }

        /// <summary>
        /// 写纯文本响应（授权端点校验失败时不得重定向，直接 400 文本）。
        /// </summary>
        public static async Task WriteTextAsync(HttpContext context, int statusCode, string text)
        {
            context.Response.StatusCode = statusCode;
            context.Response.ContentType = "text/plain; charset=utf-8";
            await context.Response.WriteAsync(text, context.RequestAborted).ConfigureAwait(false);
        }

        /// <summary>
        /// 获取对外基地址：配置了 PublicOrigin 用之，否则取当前请求 scheme://host。
        /// </summary>
        public static string GetOrigin(HttpContext context, CyaimAuthServerOptions options)
        {
            if (!string.IsNullOrEmpty(options.PublicOrigin))
            {
                return options.PublicOrigin!.TrimEnd('/');
            }
            return context.Request.Scheme + "://" + context.Request.Host.Value;
        }

        /// <summary>
        /// 校验登录后跳转地址，防开放重定向：仅允许本站相对路径（"/x"，排除 "//" 与 "/\"）
        /// 或以本请求 origin 开头（后跟 / ? # 或完全相等）。
        /// </summary>
        public static bool IsSafeReturnUrl(HttpContext context, string? returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl))
            {
                return false;
            }

            string url = returnUrl!;

            // 拒绝控制字符（CR/LF 等），防响应头注入
            foreach (char c in url)
            {
                if (c < ' ' || c == '\x7f')
                {
                    return false;
                }
            }

            if (url[0] == '/')
            {
                // 拒绝协议相对地址 //evil.com 与 /\evil.com
                return url.Length == 1 || (url[1] != '/' && url[1] != '\\');
            }

            string origin = context.Request.Scheme + "://" + context.Request.Host.Value;
            if (!url.StartsWith(origin, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            if (url.Length == origin.Length)
            {
                return true;
            }
            char next = url[origin.Length];
            return next == '/' || next == '?' || next == '#';
        }

        /// <summary>
        /// 判断请求是否同源（用于登录 CSRF 防护）。优先校验 Origin 头，缺失时回退 Referer；
        /// 两者都缺失时按同源处理（部分老浏览器/非浏览器客户端不发送这些头，登录本身仍需正确凭据）。
        /// </summary>
        public static bool IsSameOriginRequest(HttpContext context)
        {
            string selfHost = context.Request.Host.Value ?? string.Empty;

            string origin = context.Request.Headers["Origin"].ToString();
            if (!string.IsNullOrEmpty(origin))
            {
                return Uri.TryCreate(origin, UriKind.Absolute, out Uri? originUri) &&
                       string.Equals(originUri.Authority, selfHost, StringComparison.OrdinalIgnoreCase);
            }

            string referer = context.Request.Headers["Referer"].ToString();
            if (!string.IsNullOrEmpty(referer))
            {
                return Uri.TryCreate(referer, UriKind.Absolute, out Uri? refererUri) &&
                       string.Equals(refererUri.Authority, selfHost, StringComparison.OrdinalIgnoreCase);
            }

            // 无 Origin 也无 Referer：不阻断（避免误伤合法非浏览器提交）
            return true;
        }

        /// <summary>
        /// 按空格拆分 scope 参数（RFC 6749 §3.3）。
        /// </summary>
        public static List<string> SplitScopes(StringValues scopeValues)
        {
            var result = new List<string>();
            foreach (string? value in scopeValues)
            {
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }
                foreach (string scope in value!.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!result.Contains(scope))
                    {
                        result.Add(scope);
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// 判断请求的作用域是否全部在允许列表内。
        /// </summary>
        public static bool ScopesAllowed(IReadOnlyList<string> requested, IReadOnlyList<string> allowed)
        {
            foreach (string scope in requested)
            {
                bool found = false;
                foreach (string allow in allowed)
                {
                    if (string.Equals(scope, allow, StringComparison.Ordinal))
                    {
                        found = true;
                        break;
                    }
                }
                if (!found)
                {
                    return false;
                }
            }
            return true;
        }
    }
}
