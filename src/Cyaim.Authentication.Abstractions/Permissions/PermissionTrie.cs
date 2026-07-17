using System;
using System.Collections.Generic;

namespace Cyaim.Authentication.Abstractions.Permissions
{
    /// <summary>
    /// 通配符权限模式字典树。仅存放含通配符的模式；精确代码走哈希表快路径。
    /// 匹配复杂度 O(段数)，含 <c>*</c> 回溯时最坏 O(段数 × 分支数)，模式层级通常很浅。
    /// </summary>
    internal sealed class PermissionTrie
    {
        private sealed class Node
        {
            /// <summary>子节点，键为段文本（已小写）</summary>
            public Dictionary<string, Node>? Children;
            /// <summary>单段通配符 * 子节点</summary>
            public Node? Star;
            /// <summary>该节点存在 ** 模式：匹配此处起零个或多个段</summary>
            public bool MatchAnyBelow;
            /// <summary>某模式恰好在该节点结束</summary>
            public bool IsTerminal;
        }

        private readonly Node _root = new Node();
        private int _count;

        /// <summary>已加入的模式数</summary>
        public int Count => _count;

        /// <summary>
        /// 加入一个已规范化、已分段的通配符模式。
        /// </summary>
        public void Add(string[] segments)
        {
            Node node = _root;
            for (int i = 0; i < segments.Length; i++)
            {
                string seg = segments[i];
                if (seg == PermissionCode.MultiWildcard)
                {
                    // ** 仅允许末段（PermissionCode 已校验）
                    node.MatchAnyBelow = true;
                    _count++;
                    return;
                }

                if (seg == PermissionCode.SingleWildcard)
                {
                    node = node.Star ?? (node.Star = new Node());
                    continue;
                }

                node.Children ??= new Dictionary<string, Node>(StringComparer.Ordinal);
                if (!node.Children.TryGetValue(seg, out Node? child))
                {
                    child = new Node();
                    node.Children[seg] = child;
                }
                node = child;
            }

            node.IsTerminal = true;
            _count++;
        }

        /// <summary>
        /// 判断查询是否命中任一模式。
        /// </summary>
        public bool Matches(in PermissionQuery query)
        {
            if (_count == 0)
            {
                return false;
            }
            return MatchesCore(_root, query.Segments, 0);
        }

        private static bool MatchesCore(Node node, string[] segments, int index)
        {
            // ** 覆盖当前及所有后续段（零或多段）
            if (node.MatchAnyBelow)
            {
                return true;
            }

            if (index == segments.Length)
            {
                return node.IsTerminal;
            }

            string seg = segments[index];

            if (node.Children != null && node.Children.TryGetValue(seg, out Node? child))
            {
                if (MatchesCore(child, segments, index + 1))
                {
                    return true;
                }
            }

            if (node.Star != null)
            {
                return MatchesCore(node.Star, segments, index + 1);
            }

            return false;
        }
    }
}
