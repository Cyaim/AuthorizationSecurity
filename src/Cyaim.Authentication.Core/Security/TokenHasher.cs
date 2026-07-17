using System;
using System.Security.Cryptography;
using System.Text;

namespace Cyaim.Authentication.Core.Security
{
    /// <summary>
    /// 不透明令牌（刷新令牌、授权码）生成与哈希。存储仅保存哈希，明文只出现在响应中。
    /// </summary>
    public static class TokenHasher
    {
        /// <summary>
        /// 生成加密安全的随机令牌（Base64URL，默认 32 字节熵）。
        /// </summary>
        public static string CreateToken(int byteLength = 32)
        {
            byte[] bytes = new byte[byteLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Base64Url.Encode(bytes);
        }

        /// <summary>
        /// 计算令牌哈希：Base64URL(SHA-256(UTF8(token)))。
        /// </summary>
        public static string HashToken(string token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Base64Url.Encode(hash);
        }
    }
}
