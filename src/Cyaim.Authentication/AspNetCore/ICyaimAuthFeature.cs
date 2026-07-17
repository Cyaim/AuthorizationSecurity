using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// 请求级鉴权特征：中间件解析后的主体与令牌状态。
    /// </summary>
    public interface ICyaimAuthFeature
    {
        /// <summary>当前请求主体（未认证时为游客）</summary>
        AuthSubject Subject { get; }

        /// <summary>令牌解析状态</summary>
        TokenState TokenState { get; }
    }

    /// <summary>令牌解析状态</summary>
    public enum TokenState
    {
        /// <summary>请求未携带令牌</summary>
        None = 0,
        /// <summary>令牌有效</summary>
        Valid = 1,
        /// <summary>令牌无效或过期</summary>
        Invalid = 2,
    }

    internal sealed class CyaimAuthFeature : ICyaimAuthFeature
    {
        public CyaimAuthFeature(AuthSubject subject, TokenState tokenState)
        {
            Subject = subject;
            TokenState = tokenState;
        }

        public AuthSubject Subject { get; }

        public TokenState TokenState { get; }
    }
}
