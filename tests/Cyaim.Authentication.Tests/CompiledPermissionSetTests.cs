using System;
using Cyaim.Authentication.Abstractions.Permissions;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="CompiledPermissionSet"/> 构建与匹配测试。
    /// </summary>
    public class CompiledPermissionSetTests
    {
        [Fact]
        public void 精确代码_命中与未命中()
        {
            var set = CompiledPermissionSet.Build(new[] { "doc.read", "doc.write" });

            Assert.True(set.IsGranted("doc.read"));
            Assert.True(set.IsGranted("doc.write"));
            Assert.False(set.IsGranted("doc.delete"));
            Assert.False(set.IsGranted("doc"));
        }

        [Fact]
        public void 单段通配符_只匹配恰好一段()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.*" });

            Assert.True(set.IsGranted("a.b"));
            Assert.False(set.IsGranted("a.b.c"));
            Assert.False(set.IsGranted("a"));
        }

        [Fact]
        public void 多段通配符_匹配自身与全部下级()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.**" });

            Assert.True(set.IsGranted("a"));
            Assert.True(set.IsGranted("a.b"));
            Assert.True(set.IsGranted("a.b.c"));
            Assert.False(set.IsGranted("b"));
            Assert.False(set.IsGranted("ab"));
        }

        [Fact]
        public void 单段通配符_可在中段()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.*.c" });

            Assert.True(set.IsGranted("a.b.c"));
            Assert.True(set.IsGranted("a.x.c"));
            Assert.False(set.IsGranted("a.c"));
            Assert.False(set.IsGranted("a.b.d"));
            Assert.False(set.IsGranted("a.b.c.d"));
        }

        [Fact]
        public void 回溯_具体分支不匹配时回退到通配分支()
        {
            // 同时存在 a.b.**（具体段 b）与 a.*.x（通配段）：
            // 查询 a.c.x 应先尝试 b 分支失败后经 * 分支命中
            var set = CompiledPermissionSet.Build(new[] { "a.b.**", "a.*.x" });

            Assert.True(set.IsGranted("a.c.x"));
            Assert.True(set.IsGranted("a.b.anything"));
            Assert.True(set.IsGranted("a.b.x"));
            Assert.False(set.IsGranted("a.c.y"));
        }

        [Fact]
        public void 拒绝优先_deny覆盖allow()
        {
            var set = CompiledPermissionSet.Build(
                allowCodes: new[] { "a.**" },
                denyCodes: new[] { "a.b" });

            Assert.Equal(PermissionEffect.Deny, set.Evaluate("a.b"));
            Assert.False(set.IsGranted("a.b"));
            Assert.Equal(PermissionEffect.Allow, set.Evaluate("a.c"));
            Assert.True(set.IsGranted("a.c"));
        }

        [Fact]
        public void 拒绝优先_通配deny覆盖精确allow()
        {
            var set = CompiledPermissionSet.Build(
                allowCodes: new[] { "sys.user.read" },
                denyCodes: new[] { "sys.**" });

            Assert.Equal(PermissionEffect.Deny, set.Evaluate("sys.user.read"));
        }

        [Fact]
        public void 非法代码被忽略_不抛异常()
        {
            var set = CompiledPermissionSet.Build(new[] { "", "a..b", "us*", "a.***", "**.a", "valid.code", null! });

            Assert.True(set.IsGranted("valid.code"));
            Assert.Single(set.Allows);
            Assert.Equal("valid.code", set.Allows[0]);
        }

        [Fact]
        public void 大小写不敏感()
        {
            var set = CompiledPermissionSet.Build(new[] { "SYS.User.Read" });

            Assert.True(set.IsGranted("sys.user.read"));
            Assert.True(set.IsGranted("SYS.USER.READ"));
        }

        [Fact]
        public void 冒号与点等价()
        {
            var set = CompiledPermissionSet.Build(new[] { "sys:user.read" });

            Assert.True(set.IsGranted("sys.user.read"));
            Assert.True(set.IsGranted("sys:user:read"));
        }

        [Fact]
        public void 空集_评估为NotSet()
        {
            Assert.Equal(PermissionEffect.NotSet, CompiledPermissionSet.Empty.Evaluate("a.b"));
            Assert.False(CompiledPermissionSet.Empty.IsGranted("a.b"));
            Assert.Empty(CompiledPermissionSet.Empty.Allows);
            Assert.Empty(CompiledPermissionSet.Empty.Denies);
        }

        [Fact]
        public void 非法查询代码_评估为NotSet()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.**" });

            Assert.Equal(PermissionEffect.NotSet, set.Evaluate("bad..code"));
            Assert.Equal(PermissionEffect.NotSet, set.Evaluate(""));
        }

        [Fact]
        public void 重复代码去重()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.b", "a.b", "A.B", "a:b" });

            Assert.Single(set.Allows);
            Assert.True(set.IsGranted("a.b"));
        }

        [Fact]
        public void StoreVersion_保留传入版本戳()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.b" }, null, storeVersion: 42);

            Assert.Equal(42, set.StoreVersion);
        }

        [Fact]
        public void PermissionQuery重载_与字符串重载一致()
        {
            var set = CompiledPermissionSet.Build(new[] { "a.*" });
            PermissionQuery query = PermissionQuery.Parse("a.b");

            Assert.True(set.IsGranted(query));
            Assert.Equal(PermissionEffect.Allow, set.Evaluate(query));
            Assert.Equal(PermissionEffect.NotSet, set.Evaluate(default(PermissionQuery)));
        }
    }
}
