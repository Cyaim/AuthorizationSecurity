using System;
using System.Security.Cryptography;
using System.Text;
using Cyaim.Authentication.Abstractions.Services;

namespace Cyaim.Authentication.Core.Security
{
    /// <summary>
    /// PBKDF2-HMAC-SHA256 口令哈希（NIST SP 800-132）。
    /// 格式：<c>PBKDF2-SHA256$迭代次数$盐Base64$哈希Base64</c>，参数自描述，可平滑升级迭代次数。
    /// </summary>
    public sealed class Pbkdf2PasswordHasher : IPasswordHasher
    {
        private const string Prefix = "PBKDF2-SHA256";
        private const int SaltSize = 16;
        private const int KeySize = 32;
        private const int DefaultIterations = 100_000;

        private readonly int _iterations;

        /// <summary>使用默认迭代次数（100,000）</summary>
        public Pbkdf2PasswordHasher() : this(DefaultIterations) { }

        /// <summary>指定迭代次数</summary>
        public Pbkdf2PasswordHasher(int iterations)
        {
            if (iterations < 1000)
            {
                throw new ArgumentOutOfRangeException(nameof(iterations), "迭代次数不能低于 1000");
            }
            _iterations = iterations;
        }

        /// <inheritdoc/>
        public string Hash(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] key = DeriveKey(password, salt, _iterations, KeySize);
            return $"{Prefix}${_iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
        }

        /// <inheritdoc/>
        public bool Verify(string hash, string password)
        {
            if (string.IsNullOrEmpty(hash) || password == null)
            {
                return false;
            }

            string[] parts = hash.Split('$');
            if (parts.Length != 4 || parts[0] != Prefix)
            {
                return false;
            }

            if (!int.TryParse(parts[1], out int iterations) || iterations < 1)
            {
                return false;
            }

            byte[] salt;
            byte[] expected;
            try
            {
                salt = Convert.FromBase64String(parts[2]);
                expected = Convert.FromBase64String(parts[3]);
            }
            catch (FormatException)
            {
                return false;
            }

            // 拒绝退化哈希：末段为空时 DeriveKey 会派生零长度密钥，FixedTimeEquals(空, 空) 恒为 true，
            // 任意口令都会通过（存储中出现畸形/损坏/被篡改的空哈希将导致口令校验绕过）。空盐同理拒绝。
            // 正常创建的哈希盐 16 字节、密钥 32 字节，永远不会命中此分支。
            if (salt.Length == 0 || expected.Length == 0)
            {
                return false;
            }

            byte[] actual = DeriveKey(password, salt, iterations, expected.Length);
            return FixedTimeEquals(expected, actual);
        }

        /// <summary>
        /// PBKDF2-HMAC-SHA256（RFC 2898 §5.2）。手写实现以保证 netstandard2.0 下同样使用 SHA256。
        /// </summary>
        internal static byte[] DeriveKey(string password, byte[] salt, int iterations, int keyLength)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password));
            int blockCount = (keyLength + 31) / 32;
            byte[] output = new byte[blockCount * 32];

            byte[] saltBlock = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltBlock, 0, salt.Length);

            for (int block = 1; block <= blockCount; block++)
            {
                saltBlock[salt.Length] = (byte)(block >> 24);
                saltBlock[salt.Length + 1] = (byte)(block >> 16);
                saltBlock[salt.Length + 2] = (byte)(block >> 8);
                saltBlock[salt.Length + 3] = (byte)block;

                byte[] u = hmac.ComputeHash(saltBlock);
                byte[] t = (byte[])u.Clone();

                for (int i = 1; i < iterations; i++)
                {
                    u = hmac.ComputeHash(u);
                    for (int j = 0; j < 32; j++)
                    {
                        t[j] ^= u[j];
                    }
                }

                Buffer.BlockCopy(t, 0, output, (block - 1) * 32, 32);
            }

            if (output.Length == keyLength)
            {
                return output;
            }

            byte[] result = new byte[keyLength];
            Buffer.BlockCopy(output, 0, result, 0, keyLength);
            return result;
        }

        /// <summary>常量时间比较，防时序侧信道</summary>
        internal static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
