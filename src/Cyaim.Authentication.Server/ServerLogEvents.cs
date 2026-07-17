using Microsoft.Extensions.Logging;

namespace Cyaim.Authentication.Server
{
    /// <summary>
    /// 授权服务器日志事件Id（结构化日志过滤用，3xxx 段）。
    /// </summary>
    public static class ServerLogEvents
    {
        /// <summary>令牌端点签发成功</summary>
        public static readonly EventId TokenGranted = new EventId(3001, nameof(TokenGranted));
        /// <summary>令牌端点拒绝请求</summary>
        public static readonly EventId TokenRejected = new EventId(3002, nameof(TokenRejected));
        /// <summary>客户端认证失败</summary>
        public static readonly EventId ClientAuthFailed = new EventId(3003, nameof(ClientAuthFailed));
        /// <summary>授权端点签发授权码</summary>
        public static readonly EventId AuthorizationCodeIssued = new EventId(3004, nameof(AuthorizationCodeIssued));
        /// <summary>授权端点拒绝请求</summary>
        public static readonly EventId AuthorizeRejected = new EventId(3005, nameof(AuthorizeRejected));
        /// <summary>SSO 会话签发</summary>
        public static readonly EventId SsoSessionIssued = new EventId(3006, nameof(SsoSessionIssued));
        /// <summary>SSO 会话清除（登出）</summary>
        public static readonly EventId SsoSessionCleared = new EventId(3007, nameof(SsoSessionCleared));
        /// <summary>SSO Cookie 签名密钥生成</summary>
        public static readonly EventId SsoKeyGenerated = new EventId(3008, nameof(SsoKeyGenerated));
        /// <summary>令牌吊销</summary>
        public static readonly EventId TokenRevoked = new EventId(3009, nameof(TokenRevoked));
    }
}
