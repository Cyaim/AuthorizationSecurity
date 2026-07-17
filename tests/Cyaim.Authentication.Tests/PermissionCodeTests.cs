using System;
using Cyaim.Authentication.Abstractions.Permissions;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="PermissionCode"/> 规范化与校验测试。
    /// </summary>
    public class PermissionCodeTests
    {
        [Theory]
        [InlineData("SYS.User.Read", "sys.user.read")]
        [InlineData("sys.user.read", "sys.user.read")]
        [InlineData("A", "a")]
        public void Normalize_转小写(string input, string expected)
        {
            Assert.Equal(expected, PermissionCode.Normalize(input));
        }

        [Theory]
        [InlineData("sys:user:read", "sys.user.read")]
        [InlineData("sys:user.read", "sys.user.read")]
        [InlineData("Prefix:Controller.Action", "prefix.controller.action")]
        public void Normalize_冒号与点等价(string input, string expected)
        {
            Assert.Equal(expected, PermissionCode.Normalize(input));
        }

        [Theory]
        [InlineData("  sys.user  ", "sys.user")]
        [InlineData("\tsys.user\r\n", "sys.user")]
        public void Normalize_去首尾空白(string input, string expected)
        {
            Assert.Equal(expected, PermissionCode.Normalize(input));
        }

        [Theory]
        [InlineData("*")]
        [InlineData("**")]
        [InlineData("sys.*.read")]
        [InlineData("sys.**")]
        public void Normalize_合法通配符原样保留(string input)
        {
            Assert.Equal(input, PermissionCode.Normalize(input));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void Normalize_空输入抛异常(string? input)
        {
            Assert.Throws<ArgumentException>(() => PermissionCode.Normalize(input!));
        }

        [Theory]
        [InlineData("a..b")]
        [InlineData("a.")]
        [InlineData(".a")]
        [InlineData("a::b")]
        public void TryNormalize_空段失败(string input)
        {
            Assert.False(PermissionCode.TryNormalize(input, out _, out string? error));
            Assert.NotNull(error);
            Assert.Contains("空段", error);
        }

        [Theory]
        [InlineData("a.b!c")]
        [InlineData("a b")]
        [InlineData("a.b/c")]
        [InlineData("a.b#c")]
        public void TryNormalize_非法字符失败(string input)
        {
            Assert.False(PermissionCode.TryNormalize(input, out _, out string? error));
            Assert.NotNull(error);
            Assert.Contains("非法字符", error);
        }

        [Theory]
        [InlineData("us*")]
        [InlineData("sys.us*")]
        [InlineData("*us")]
        [InlineData("sys.a*b")]
        public void TryNormalize_部分通配失败(string input)
        {
            Assert.False(PermissionCode.TryNormalize(input, out _, out string? error));
            Assert.NotNull(error);
            Assert.Contains("独占", error);
        }

        [Theory]
        [InlineData("***")]
        [InlineData("a.***")]
        [InlineData("a.****")]
        public void TryNormalize_超过两星失败(string input)
        {
            Assert.False(PermissionCode.TryNormalize(input, out _, out string? error));
            Assert.NotNull(error);
            Assert.Contains("仅允许 * 或 **", error);
        }

        [Theory]
        [InlineData("**.a")]
        [InlineData("a.**.b")]
        public void TryNormalize_多段通配符不在末段失败(string input)
        {
            Assert.False(PermissionCode.TryNormalize(input, out _, out string? error));
            Assert.NotNull(error);
            Assert.Contains("最后一段", error);
        }

        [Fact]
        public void TryNormalize_空输入返回错误信息()
        {
            Assert.False(PermissionCode.TryNormalize("", out string normalized, out string? error));
            Assert.Equal(string.Empty, normalized);
            Assert.Equal("权限代码不能为空", error);
        }

        [Fact]
        public void TryNormalize_成功时error为空()
        {
            Assert.True(PermissionCode.TryNormalize("SYS:User", out string normalized, out string? error));
            Assert.Equal("sys.user", normalized);
            Assert.Null(error);
        }

        [Fact]
        public void Normalize_允许字母数字下划线连字符()
        {
            Assert.Equal("sys_a.user-b.read2", PermissionCode.Normalize("Sys_A.User-B.Read2"));
        }

        [Fact]
        public void Split_按点分段()
        {
            Assert.Equal(new[] { "a", "b", "c" }, PermissionCode.Split("a.b.c"));
        }

        [Theory]
        [InlineData("a.b", false)]
        [InlineData("a.*", true)]
        [InlineData("a.**", true)]
        public void HasWildcard_检测通配符(string code, bool expected)
        {
            Assert.Equal(expected, PermissionCode.HasWildcard(code));
        }
    }
}
