using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Permissions
{
    /// <summary>
    /// 编译后的主体权限集：构建一次，检查 O(1)（精确命中）/ O(段数)（通配符）。
    /// 语义：拒绝优先（Deny-Override）。线程安全（构建后不可变）。
    /// </summary>
    public sealed class CompiledPermissionSet
    {
        /// <summary>空权限集（一切检查返回 <see cref="PermissionEffect.NotSet"/>）</summary>
        public static readonly CompiledPermissionSet Empty = Build(Array.Empty<string>());

        private readonly HashSet<string> _exactAllows;
        private readonly HashSet<string> _exactDenies;
        private readonly PermissionTrie _wildcardAllows;
        private readonly PermissionTrie _wildcardDenies;
        private readonly string[] _allows;
        private readonly string[] _denies;

        /// <summary>构建该权限集时的存储版本号，用于缓存失效判断</summary>
        public long StoreVersion { get; }

        private CompiledPermissionSet(
            HashSet<string> exactAllows, HashSet<string> exactDenies,
            PermissionTrie wildcardAllows, PermissionTrie wildcardDenies,
            string[] allows, string[] denies, long storeVersion)
        {
            _exactAllows = exactAllows;
            _exactDenies = exactDenies;
            _wildcardAllows = wildcardAllows;
            _wildcardDenies = wildcardDenies;
            _allows = allows;
            _denies = denies;
            StoreVersion = storeVersion;
        }

        /// <summary>规范化后的允许代码列表</summary>
        public IReadOnlyList<string> Allows => _allows;

        /// <summary>规范化后的拒绝代码列表</summary>
        public IReadOnlyList<string> Denies => _denies;

        /// <summary>
        /// 从允许/拒绝代码构建权限集。非法代码将被忽略（保证已有数据坏值不阻断鉴权，只收紧权限）。
        /// </summary>
        /// <param name="allowCodes">允许的权限代码</param>
        /// <param name="denyCodes">拒绝的权限代码（优先级更高）</param>
        /// <param name="storeVersion">数据版本戳</param>
        public static CompiledPermissionSet Build(
            IEnumerable<string> allowCodes,
            IEnumerable<string>? denyCodes = null,
            long storeVersion = 0)
        {
            var exactAllows = new HashSet<string>(StringComparer.Ordinal);
            var exactDenies = new HashSet<string>(StringComparer.Ordinal);
            var wildcardAllows = new PermissionTrie();
            var wildcardDenies = new PermissionTrie();
            var allows = new List<string>();
            var denies = new List<string>();

            Ingest(allowCodes, exactAllows, wildcardAllows, allows);
            if (denyCodes != null)
            {
                Ingest(denyCodes, exactDenies, wildcardDenies, denies);
            }

            return new CompiledPermissionSet(
                exactAllows, exactDenies, wildcardAllows, wildcardDenies,
                allows.ToArray(), denies.ToArray(), storeVersion);
        }

        private static void Ingest(IEnumerable<string> codes, HashSet<string> exact, PermissionTrie trie, List<string> normalizedOut)
        {
            foreach (string code in codes)
            {
                if (code == null || !PermissionCode.TryNormalize(code, out string normalized))
                {
                    continue;
                }

                if (PermissionCode.HasWildcard(normalized))
                {
                    trie.Add(PermissionCode.Split(normalized));
                }
                else if (!exact.Add(normalized))
                {
                    continue; // 去重
                }

                normalizedOut.Add(normalized);
            }
        }

        /// <summary>
        /// 判断权限是否被授予（Allow 且未被 Deny）。
        /// </summary>
        public bool IsGranted(in PermissionQuery query) => Evaluate(query) == PermissionEffect.Allow;

        /// <summary>
        /// 判断权限是否被授予（Allow 且未被 Deny）。热路径建议用 <see cref="PermissionQuery"/> 重载。
        /// </summary>
        public bool IsGranted(string permissionCode) => Evaluate(permissionCode) == PermissionEffect.Allow;

        /// <summary>
        /// 评估权限效果。拒绝优先。
        /// </summary>
        public PermissionEffect Evaluate(string permissionCode)
        {
            if (!PermissionQuery.TryParse(permissionCode, out PermissionQuery query))
            {
                return PermissionEffect.NotSet;
            }
            return Evaluate(query);
        }

        /// <summary>
        /// 评估权限效果。拒绝优先。
        /// </summary>
        public PermissionEffect Evaluate(in PermissionQuery query)
        {
            if (query.IsEmpty)
            {
                return PermissionEffect.NotSet;
            }

            if (_exactDenies.Contains(query.Code) || _wildcardDenies.Matches(query))
            {
                return PermissionEffect.Deny;
            }

            if (_exactAllows.Contains(query.Code) || _wildcardAllows.Matches(query))
            {
                return PermissionEffect.Allow;
            }

            return PermissionEffect.NotSet;
        }
    }
}
