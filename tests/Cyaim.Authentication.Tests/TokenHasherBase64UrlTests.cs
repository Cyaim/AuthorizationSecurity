using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Cyaim.Authentication.Core.Security;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="TokenHasher"/> 与 <see cref="Base64Url"/> 测试。
    /// </summary>
    public class TokenHasherBase64UrlTests
    {
        [Fact]
        public void CreateToken_默认32字节熵()
        {
            string token = TokenHasher.CreateToken();

            byte[] decoded = Base64Url.Decode(token);
            Assert.Equal(32, decoded.Length);
        }

        [Fact]
        public void CreateToken_指定长度()
        {
            Assert.Equal(16, Base64Url.Decode(TokenHasher.CreateToken(16)).Length);
            Assert.Equal(64, Base64Url.Decode(TokenHasher.CreateToken(64)).Length);
        }

        [Fact]
        public void CreateToken_随机唯一()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < 100; i++)
            {
                Assert.True(seen.Add(TokenHasher.CreateToken()));
            }
        }

        [Fact]
        public void HashToken_确定性且与SHA256一致()
        {
            string h1 = TokenHasher.HashToken("abc");
            string h2 = TokenHasher.HashToken("abc");
            string h3 = TokenHasher.HashToken("abd");

            Assert.Equal(h1, h2);
            Assert.NotEqual(h1, h3);

            using var sha = SHA256.Create();
            string expected = Base64Url.Encode(sha.ComputeHash(Encoding.UTF8.GetBytes("abc")));
            Assert.Equal(expected, h1);
        }

        [Fact]
        public void HashToken_null抛异常()
        {
            Assert.Throws<ArgumentNullException>(() => TokenHasher.HashToken(null!));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(31)]
        [InlineData(32)]
        [InlineData(33)]
        public void Base64Url_编解码往返_覆盖padding边界(int length)
        {
            byte[] data = new byte[length];
            for (int i = 0; i < length; i++)
            {
                data[i] = (byte)(i * 37 + 11);
            }

            string encoded = Base64Url.Encode(data);
            Assert.Equal(data, Base64Url.Decode(encoded));
        }

        [Fact]
        public void Base64Url_输出不含填充与URL不安全字符()
        {
            // 0xFF/0xFE/0xFB 组合在标准 Base64 中会产生 '+' 与 '/'
            byte[] data = { 0xFF, 0xFE, 0xFB, 0xFF, 0xEF, 0x3F };

            string encoded = Base64Url.Encode(data);

            Assert.DoesNotContain("+", encoded, StringComparison.Ordinal);
            Assert.DoesNotContain("/", encoded, StringComparison.Ordinal);
            Assert.DoesNotContain("=", encoded, StringComparison.Ordinal);
            Assert.Equal(data, Base64Url.Decode(encoded));
        }

        [Fact]
        public void Base64Url_已知值()
        {
            // "f" → "Zg"（RFC 4648 测试向量去填充）
            Assert.Equal("Zg", Base64Url.Encode(Encoding.ASCII.GetBytes("f")));
            // "fo" → "Zm8"
            Assert.Equal("Zm8", Base64Url.Encode(Encoding.ASCII.GetBytes("fo")));
            // "foo" → "Zm9v"
            Assert.Equal("Zm9v", Base64Url.Encode(Encoding.ASCII.GetBytes("foo")));
        }
    }
}
