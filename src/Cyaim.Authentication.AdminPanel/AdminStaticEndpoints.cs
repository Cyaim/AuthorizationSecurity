using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Cyaim.Authentication.AdminPanel
{
    /// <summary>
    /// 内嵌 SPA 静态资源服务：从程序集嵌入资源读取文件并做内存缓存。
    /// </summary>
    internal static class AdminStaticEndpoints
    {
        /// <summary>嵌入资源名前缀（默认命名空间 + EmbeddedUI 目录，'/' 已转为 '.'）</summary>
        private const string ResourcePrefix = "Cyaim.Authentication.AdminPanel.EmbeddedUI.";

        private static readonly ConcurrentDictionary<string, EmbeddedFile> Cache =
            new ConcurrentDictionary<string, EmbeddedFile>(StringComparer.Ordinal);

        // 启动时枚举一次嵌入资源全名集合（固定且很小）。仅白名单内的资源名才会被服务与缓存，
        // 任意未知路径直接 404 且不写缓存——避免游客用无限唯一路径撑爆内存。
        private static readonly HashSet<string> KnownResourceNames = LoadKnownResourceNames();

        private static HashSet<string> LoadKnownResourceNames()
        {
            var set = new HashSet<string>(StringComparer.Ordinal);
            foreach (string name in typeof(AdminStaticEndpoints).Assembly.GetManifestResourceNames())
            {
                if (name.StartsWith(ResourcePrefix, StringComparison.Ordinal))
                {
                    set.Add(name);
                }
            }
            return set;
        }

        /// <summary>
        /// 注册静态资源端点（面板首页与资源文件，允许游客访问以展示登录页）。
        /// </summary>
        internal static void Map(RouteGroupBuilder group)
        {
            // GET {base} → index.html
            group.MapGet(string.Empty, () => Serve("index.html")).AllowGuest();
            // GET {base}/ 与 GET {base}/xxx → 对应嵌入文件（空路径回落到 index.html）
            group.MapGet("/{**assetPath}", (string? assetPath) =>
                Serve(string.IsNullOrEmpty(assetPath) ? "index.html" : assetPath!)).AllowGuest();
        }

        private static IResult Serve(string relativePath)
        {
            string resourceName = ResourcePrefix + relativePath.Replace('/', '.').Replace('\\', '.');
            // 只服务白名单内的固定资源；未知路径直接 404，绝不写缓存（缓存规模因此有上界）
            if (!KnownResourceNames.Contains(resourceName))
            {
                return Results.NotFound();
            }

            if (!Cache.TryGetValue(resourceName, out EmbeddedFile? file))
            {
                file = Load(resourceName, relativePath);
                if (file == null)
                {
                    return Results.NotFound();
                }
                Cache.TryAdd(resourceName, file);
            }
            return Results.Bytes(file.Content, file.ContentType);
        }

        private static EmbeddedFile? Load(string resourceName, string relativePath)
        {
            Assembly assembly = typeof(AdminStaticEndpoints).Assembly;
            using (Stream? stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    return null;
                }
                using (var buffer = new MemoryStream())
                {
                    stream.CopyTo(buffer);
                    return new EmbeddedFile(buffer.ToArray(), GetContentType(relativePath));
                }
            }
        }

        private static string GetContentType(string path)
        {
            string extension = Path.GetExtension(path);
            switch (extension.ToLowerInvariant())
            {
                case ".html": return "text/html; charset=utf-8";
                case ".js": return "text/javascript; charset=utf-8";
                case ".css": return "text/css; charset=utf-8";
                case ".json": return "application/json; charset=utf-8";
                case ".svg": return "image/svg+xml";
                case ".png": return "image/png";
                case ".jpg":
                case ".jpeg": return "image/jpeg";
                case ".gif": return "image/gif";
                case ".ico": return "image/x-icon";
                case ".woff": return "font/woff";
                case ".woff2": return "font/woff2";
                case ".map": return "application/json";
                case ".txt": return "text/plain; charset=utf-8";
                default: return "application/octet-stream";
            }
        }

        private sealed class EmbeddedFile
        {
            public byte[] Content { get; }
            public string ContentType { get; }

            public EmbeddedFile(byte[] content, string contentType)
            {
                Content = content;
                ContentType = contentType;
            }
        }
    }
}
