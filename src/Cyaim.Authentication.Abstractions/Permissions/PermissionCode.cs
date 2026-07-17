using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Permissions
{
    /// <summary>
    /// 权限代码规范与解析。
    /// <para>
    /// 权限代码为分层结构，段之间用 <c>.</c> 或 <c>:</c> 分隔（两者等价，规范化后统一为 <c>.</c>），
    /// 不区分大小写。例如：<c>sys:user.read</c> 规范化为 <c>sys.user.read</c>。
    /// </para>
    /// <para>
    /// 通配符：<c>*</c> 匹配恰好一个段；<c>**</c> 匹配零个或多个段，仅允许作为最后一段。
    /// 例如授权 <c>sys.user.*</c> 匹配 <c>sys.user.read</c> 但不匹配 <c>sys.user.profile.read</c>；
    /// 授权 <c>sys.**</c> 匹配 <c>sys</c> 及其全部下级节点。
    /// </para>
    /// </summary>
    public static class PermissionCode
    {
        /// <summary>规范分隔符</summary>
        public const char Separator = '.';
        /// <summary>等价分隔符（兼容 1.x 的 <c>Prefix:Controller.Action</c> 风格）</summary>
        public const char AltSeparator = ':';
        /// <summary>单段通配符</summary>
        public const string SingleWildcard = "*";
        /// <summary>多段通配符（仅限末段）</summary>
        public const string MultiWildcard = "**";

        /// <summary>
        /// 规范化权限代码：去空白、统一分隔符为 <c>.</c>、转小写。
        /// </summary>
        /// <exception cref="ArgumentException">代码为空或格式非法</exception>
        public static string Normalize(string code)
        {
            if (!TryNormalize(code, out string normalized, out string? error))
            {
                throw new ArgumentException(error, nameof(code));
            }
            return normalized;
        }

        /// <summary>
        /// 尝试规范化权限代码。
        /// </summary>
        public static bool TryNormalize(string code, out string normalized) =>
            TryNormalize(code, out normalized, out _);

        /// <summary>
        /// 尝试规范化权限代码，失败时返回原因。
        /// </summary>
        public static bool TryNormalize(string code, out string normalized, out string? error)
        {
            normalized = string.Empty;
            if (string.IsNullOrWhiteSpace(code))
            {
                error = "权限代码不能为空";
                return false;
            }

            string s = code.Trim();
            char[] buffer = new char[s.Length];
            int segStart = 0;
            int write = 0;
            for (int i = 0; i <= s.Length; i++)
            {
                bool atEnd = i == s.Length;
                char c = atEnd ? Separator : s[i];
                if (c == Separator || c == AltSeparator)
                {
                    int segLen = i - segStart;
                    if (segLen == 0)
                    {
                        error = $"权限代码 \"{code}\" 含空段";
                        return false;
                    }
                    if (!ValidateSegment(s, segStart, segLen, atEnd, out error))
                    {
                        return false;
                    }
                    if (!atEnd)
                    {
                        buffer[write++] = Separator;
                    }
                    segStart = i + 1;
                    continue;
                }

                buffer[write++] = char.ToLowerInvariant(c);
            }

            normalized = new string(buffer, 0, write);
            error = null;
            return true;
        }

        /// <summary>
        /// 将规范化后的权限代码拆分为段。
        /// </summary>
        public static string[] Split(string normalizedCode)
        {
            return normalizedCode.Split(Separator);
        }

        /// <summary>
        /// 判断规范化代码是否包含通配符段。
        /// </summary>
        public static bool HasWildcard(string normalizedCode)
        {
            return normalizedCode.IndexOf('*') >= 0;
        }

        private static bool ValidateSegment(string s, int start, int length, bool isLast, out string? error)
        {
            // 通配符段必须是整段：* 或 **，** 仅允许末段
            int stars = 0;
            for (int i = start; i < start + length; i++)
            {
                char c = s[i];
                if (c == '*')
                {
                    stars++;
                    continue;
                }
                bool valid = char.IsLetterOrDigit(c) || c == '_' || c == '-';
                if (!valid)
                {
                    error = $"权限代码段含非法字符 '{c}'（允许字母、数字、_、-、*）";
                    return false;
                }
            }

            if (stars > 0)
            {
                if (stars != length)
                {
                    error = "通配符必须独占一段（如 sys.*.read），不允许部分匹配（如 sys.us*）";
                    return false;
                }
                if (stars > 2)
                {
                    error = "通配符段仅允许 * 或 **";
                    return false;
                }
                if (stars == 2 && !isLast)
                {
                    error = "多段通配符 ** 仅允许作为最后一段";
                    return false;
                }
            }

            error = null;
            return true;
        }
    }
}
