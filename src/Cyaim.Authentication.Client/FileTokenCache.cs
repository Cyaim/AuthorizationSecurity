using System;
using System.IO;
using System.Text.Json;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 文件令牌缓存：JSON 序列化到指定路径，写入原子（临时文件 + 替换）。
    /// 可通过 protect/unprotect 钩子注入平台加密（如 Windows DPAPI：
    /// <c>data => ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser)</c>）。
    /// </summary>
    public class FileTokenCache : ITokenCache
    {
        private static readonly JsonSerializerOptions s_jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = false,
        };

        private readonly string _path;
        private readonly Func<byte[], byte[]>? _protect;
        private readonly Func<byte[], byte[]>? _unprotect;
        private readonly object _sync = new object();

        /// <summary>
        /// 创建文件令牌缓存。
        /// </summary>
        /// <param name="path">缓存文件路径</param>
        /// <param name="protect">写入前加密钩子（可选）</param>
        /// <param name="unprotect">读取后解密钩子（可选，须与 <paramref name="protect"/> 配对）</param>
        public FileTokenCache(string path, Func<byte[], byte[]>? protect = null, Func<byte[], byte[]>? unprotect = null)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentException("缓存文件路径不能为空", nameof(path));
            }

            _path = path;
            _protect = protect;
            _unprotect = unprotect;
        }

        /// <inheritdoc />
        public TokenSet? Load()
        {
            lock (_sync)
            {
                try
                {
                    if (!File.Exists(_path))
                    {
                        return null;
                    }

                    byte[] data = File.ReadAllBytes(_path);
                    if (_unprotect != null)
                    {
                        data = _unprotect(data);
                    }

                    return JsonSerializer.Deserialize<TokenSet>(data, s_jsonOptions);
                }
                catch
                {
                    // 缓存损坏/解密失败视为无缓存，不阻断客户端启动
                    return null;
                }
            }
        }

        /// <inheritdoc />
        public void Save(TokenSet? tokenSet)
        {
            lock (_sync)
            {
                if (tokenSet == null)
                {
                    if (File.Exists(_path))
                    {
                        File.Delete(_path);
                    }
                    return;
                }

                byte[] data = JsonSerializer.SerializeToUtf8Bytes(tokenSet, s_jsonOptions);
                if (_protect != null)
                {
                    data = _protect(data);
                }

                string? dir = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string tmp = _path + ".tmp";
                File.WriteAllBytes(tmp, data);
                if (File.Exists(_path))
                {
                    File.Replace(tmp, _path, null);
                }
                else
                {
                    File.Move(tmp, _path);
                }
            }
        }
    }
}
