namespace Cyaim.Authentication.Abstractions.Services
{
    /// <summary>
    /// 口令哈希服务（用户口令与客户端密钥）。
    /// </summary>
    public interface IPasswordHasher
    {
        /// <summary>
        /// 生成口令哈希（应含盐与算法参数，可自验证）。
        /// </summary>
        string Hash(string password);

        /// <summary>
        /// 校验口令与哈希是否匹配（应使用常量时间比较）。
        /// </summary>
        bool Verify(string hash, string password);
    }
}
