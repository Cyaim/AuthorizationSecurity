using System;

namespace Cyaim.Authentication.Abstractions.Permissions
{
    /// <summary>
    /// 预解析的权限查询。
    /// 对固定权限代码（如端点要求的权限）预先解析一次，检查时零解析开销。
    /// </summary>
    public readonly struct PermissionQuery : IEquatable<PermissionQuery>
    {
        /// <summary>规范化后的权限代码</summary>
        public string Code { get; }

        /// <summary>代码分段</summary>
        public string[] Segments { get; }

        private PermissionQuery(string code, string[] segments)
        {
            Code = code;
            Segments = segments;
        }

        /// <summary>是否为默认空值</summary>
        public bool IsEmpty => Code == null;

        /// <summary>
        /// 解析权限代码为查询。查询代码应为具体节点，不建议包含通配符。
        /// </summary>
        /// <exception cref="ArgumentException">代码格式非法</exception>
        public static PermissionQuery Parse(string code)
        {
            string normalized = PermissionCode.Normalize(code);
            return new PermissionQuery(normalized, PermissionCode.Split(normalized));
        }

        /// <summary>
        /// 尝试解析权限代码为查询。
        /// </summary>
        public static bool TryParse(string code, out PermissionQuery query)
        {
            if (PermissionCode.TryNormalize(code, out string normalized))
            {
                query = new PermissionQuery(normalized, PermissionCode.Split(normalized));
                return true;
            }
            query = default;
            return false;
        }

        /// <inheritdoc/>
        public bool Equals(PermissionQuery other) => string.Equals(Code, other.Code, StringComparison.Ordinal);

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is PermissionQuery q && Equals(q);

        /// <inheritdoc/>
        public override int GetHashCode() => Code == null ? 0 : StringComparer.Ordinal.GetHashCode(Code);

        /// <inheritdoc/>
        public override string ToString() => Code ?? string.Empty;
    }
}
