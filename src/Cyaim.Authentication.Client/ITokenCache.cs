namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 令牌缓存：跨进程/跨会话持久化令牌，实现"重启免登录"。实现必须线程安全。
    /// </summary>
    public interface ITokenCache
    {
        /// <summary>
        /// 加载缓存的令牌。无缓存或缓存损坏时返回 null。
        /// </summary>
        TokenSet? Load();

        /// <summary>
        /// 保存令牌。传 null 表示清除缓存（登出）。
        /// </summary>
        void Save(TokenSet? tokenSet);
    }
}
