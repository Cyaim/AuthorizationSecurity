namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 进程内令牌缓存（不持久化，进程退出即失效）。适合服务端后台任务、测试场景。
    /// </summary>
    public class InMemoryTokenCache : ITokenCache
    {
        private volatile TokenSet? _tokenSet;

        /// <inheritdoc />
        public TokenSet? Load() => _tokenSet;

        /// <inheritdoc />
        public void Save(TokenSet? tokenSet) => _tokenSet = tokenSet;
    }
}
