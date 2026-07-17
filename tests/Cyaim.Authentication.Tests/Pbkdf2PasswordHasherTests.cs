using System;
using System.Text;
using Cyaim.Authentication.Core.Security;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="Pbkdf2PasswordHasher"/> 测试（含公开测试向量验证）。
    /// </summary>
    public class Pbkdf2PasswordHasherTests
    {
        private readonly Pbkdf2PasswordHasher _hasher = new Pbkdf2PasswordHasher(1000);

        [Fact]
        public void Hash_Verify_往返成功()
        {
            string hash = _hasher.Hash("P@ssw0rd!中文");

            Assert.StartsWith("PBKDF2-SHA256$", hash, StringComparison.Ordinal);
            Assert.True(_hasher.Verify(hash, "P@ssw0rd!中文"));
        }

        [Fact]
        public void Verify_错误口令返回false()
        {
            string hash = _hasher.Hash("correct");

            Assert.False(_hasher.Verify(hash, "wrong"));
            Assert.False(_hasher.Verify(hash, ""));
        }

        [Fact]
        public void Verify_篡改哈希返回false()
        {
            string hash = _hasher.Hash("secret");
            string[] parts = hash.Split('$');

            // 篡改哈希段第一个字符（保持 Base64 合法）
            char first = parts[3][0];
            parts[3] = (first == 'A' ? 'B' : 'A') + parts[3].Substring(1);
            string tampered = string.Join("$", parts);

            Assert.False(_hasher.Verify(tampered, "secret"));
        }

        [Theory]
        [InlineData("")]
        [InlineData("not-a-hash")]
        [InlineData("MD5$1000$c2FsdA==$aGFzaA==")]
        [InlineData("PBKDF2-SHA256$abc$c2FsdA==$aGFzaA==")]
        [InlineData("PBKDF2-SHA256$1000$!!!$aGFzaA==")]
        [InlineData("PBKDF2-SHA256$1000$c2FsdA==")]
        [InlineData("PBKDF2-SHA256$1000$c2FsdA==$aGFzaA==$extra")]
        public void Verify_格式非法返回false(string malformed)
        {
            Assert.False(_hasher.Verify(malformed, "any"));
        }

        [Fact]
        public void Hash_两次结果不同_盐随机()
        {
            string h1 = _hasher.Hash("same-password");
            string h2 = _hasher.Hash("same-password");

            Assert.NotEqual(h1, h2);
            // 但都能验证通过
            Assert.True(_hasher.Verify(h1, "same-password"));
            Assert.True(_hasher.Verify(h2, "same-password"));
        }

        [Fact]
        public void 构造_迭代次数过低抛异常()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(999));
        }

        /// <summary>
        /// PBKDF2-HMAC-SHA256 已知向量（RFC 7914 §11：P="passwd" S="salt" c=1 dkLen=64）。
        /// 前 32 字节：55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc
        /// （与 .NET Rfc2898DeriveBytes.Pbkdf2 交叉验证一致）。
        /// 通过构造自描述哈希串走公开 Verify 验证内部 DeriveKey 实现。
        /// </summary>
        [Fact]
        public void DeriveKey_RFC7914已知向量_32字节()
        {
            string saltB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("salt"));
            byte[] expected = HexToBytes("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
            string knownHash = $"PBKDF2-SHA256$1${saltB64}${Convert.ToBase64String(expected)}";

            Assert.True(_hasher.Verify(knownHash, "passwd"));
            // 末字节改错应验证失败
            expected[31] ^= 0x01;
            string wrongHash = $"PBKDF2-SHA256$1${saltB64}${Convert.ToBase64String(expected)}";
            Assert.False(_hasher.Verify(wrongHash, "passwd"));
        }

        /// <summary>
        /// 同一向量截断到 16 字节（PBKDF2 输出前缀性质）：55ac046e56e3089fec1691c22544b605。
        /// </summary>
        [Fact]
        public void DeriveKey_RFC7914已知向量_16字节截断()
        {
            string saltB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("salt"));
            byte[] expected = HexToBytes("55ac046e56e3089fec1691c22544b605");
            string knownHash = $"PBKDF2-SHA256$1${saltB64}${Convert.ToBase64String(expected)}";

            Assert.True(_hasher.Verify(knownHash, "passwd"));
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
