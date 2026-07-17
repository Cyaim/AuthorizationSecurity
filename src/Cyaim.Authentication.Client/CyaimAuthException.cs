using System;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 授权服务器返回的协议错误（OAuth 2.0 error / error_description）。
    /// </summary>
    public class CyaimAuthException : Exception
    {
        /// <summary>OAuth 2.0 错误代码（如 invalid_grant、invalid_client、invalid_request）</summary>
        public string Error { get; }

        /// <summary>错误描述（可能为 null）</summary>
        public string? ErrorDescription { get; }

        /// <summary>
        /// 创建协议错误异常。
        /// </summary>
        /// <param name="error">OAuth 2.0 错误代码</param>
        /// <param name="errorDescription">错误描述</param>
        public CyaimAuthException(string error, string? errorDescription = null)
            : base(string.IsNullOrEmpty(errorDescription) ? error : error + ": " + errorDescription)
        {
            Error = error;
            ErrorDescription = errorDescription;
        }
    }
}
