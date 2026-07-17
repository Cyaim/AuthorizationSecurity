using System;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// Base64URL 编码（RFC 4648 §5，无填充）。netstandard2.0 无内置实现，SDK 内部自带。
    /// </summary>
    internal static class Base64Url
    {
        /// <summary>编码</summary>
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        /// <summary>解码</summary>
        public static byte[] Decode(string encoded)
        {
            string s = encoded.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }
    }
}
