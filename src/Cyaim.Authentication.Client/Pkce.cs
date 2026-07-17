using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Cyaim.Authentication.Abstractions;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// PKCE (RFC 7636) 工具：生成 code_verifier / code_challenge，构建授权请求 URL。
    /// </summary>
    public static class Pkce
    {
        /// <summary>code_verifier 合法字符集（RFC 3986 unreserved）</summary>
        private const string VerifierChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

        /// <summary>
        /// 生成随机 code_verifier（RFC 7636 §4.1，长度 43-128 的 unreserved 字符）。
        /// </summary>
        /// <param name="length">长度，43-128，默认 64</param>
        public static string CreateCodeVerifier(int length = 64)
        {
            if (length < 43 || length > 128)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "code_verifier 长度必须在 43-128 之间");
            }

            var result = new char[length];
            var buffer = new byte[length * 2];
            int produced = 0;
            // 拒绝采样消除模偏差：66 * 3 = 198，仅接受 < 198 的字节
            const int limit = 198;
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                while (produced < length)
                {
                    rng.GetBytes(buffer);
                    for (int i = 0; i < buffer.Length && produced < length; i++)
                    {
                        if (buffer[i] < limit)
                        {
                            result[produced++] = VerifierChars[buffer[i] % VerifierChars.Length];
                        }
                    }
                }
            }

            return new string(result);
        }

        /// <summary>
        /// 计算 code_challenge = Base64Url(SHA256(code_verifier))（method=S256）。
        /// </summary>
        public static string CreateCodeChallenge(string codeVerifier)
        {
            if (string.IsNullOrEmpty(codeVerifier))
            {
                throw new ArgumentException("code_verifier 不能为空", nameof(codeVerifier));
            }

            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                return Base64Url.Encode(hash);
            }
        }

        /// <summary>
        /// 构建授权码 + PKCE 授权请求 URL（response_type=code, code_challenge_method=S256）。
        /// </summary>
        /// <param name="authority">授权服务器地址（如 https://auth.example.com，自动拼接 /connect/authorize）；也可直接传完整授权端点 URL（含路径）</param>
        /// <param name="clientId">客户端标识</param>
        /// <param name="redirectUri">回调地址</param>
        /// <param name="scopes">请求的作用域</param>
        /// <param name="state">防 CSRF 状态值（可为 null）</param>
        /// <param name="codeChallenge">由 <see cref="CreateCodeChallenge(string)"/> 生成</param>
        /// <param name="extraParams">附加查询参数（可选）</param>
        public static string BuildAuthorizeUrl(
            string authority,
            string clientId,
            string redirectUri,
            IEnumerable<string> scopes,
            string? state,
            string codeChallenge,
            IDictionary<string, string>? extraParams = null)
        {
            if (string.IsNullOrEmpty(authority))
            {
                throw new ArgumentException("authority 不能为空", nameof(authority));
            }

            string endpoint = authority.TrimEnd('/');
            // 仅有主机（无路径）时拼接默认授权端点
            if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) &&
                (uri!.AbsolutePath == "/" || uri.AbsolutePath.Length == 0))
            {
                endpoint += AuthConstants.Endpoints.Authorize;
            }

            return BuildAuthorizeUrlCore(endpoint, clientId, redirectUri, scopes, state, codeChallenge, extraParams);
        }

        /// <summary>
        /// 用发现文档中的授权端点构建授权请求 URL。
        /// </summary>
        /// <param name="discovery">发现文档（取 authorization_endpoint，相对路径按 issuer 解析）</param>
        /// <param name="clientId">客户端标识</param>
        /// <param name="redirectUri">回调地址</param>
        /// <param name="scopes">请求的作用域</param>
        /// <param name="state">防 CSRF 状态值（可为 null）</param>
        /// <param name="codeChallenge">由 <see cref="CreateCodeChallenge(string)"/> 生成</param>
        /// <param name="extraParams">附加查询参数（可选）</param>
        public static string BuildAuthorizeUrl(
            DiscoveryDocument discovery,
            string clientId,
            string redirectUri,
            IEnumerable<string> scopes,
            string? state,
            string codeChallenge,
            IDictionary<string, string>? extraParams = null)
        {
            if (discovery == null)
            {
                throw new ArgumentNullException(nameof(discovery));
            }

            string? endpoint = discovery.AuthorizationEndpoint;
            if (string.IsNullOrEmpty(endpoint))
            {
                if (string.IsNullOrEmpty(discovery.Issuer))
                {
                    throw new ArgumentException("发现文档缺少 authorization_endpoint 与 issuer", nameof(discovery));
                }
                endpoint = discovery.Issuer!.TrimEnd('/') + AuthConstants.Endpoints.Authorize;
            }
            else if (!endpoint!.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                     !endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                string issuer = (discovery.Issuer ?? string.Empty).TrimEnd('/');
                endpoint = endpoint[0] == '/' ? issuer + endpoint : issuer + "/" + endpoint;
            }

            return BuildAuthorizeUrlCore(endpoint!, clientId, redirectUri, scopes, state, codeChallenge, extraParams);
        }

        private static string BuildAuthorizeUrlCore(
            string endpoint,
            string clientId,
            string redirectUri,
            IEnumerable<string> scopes,
            string? state,
            string codeChallenge,
            IDictionary<string, string>? extraParams)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                throw new ArgumentException("clientId 不能为空", nameof(clientId));
            }
            if (string.IsNullOrEmpty(redirectUri))
            {
                throw new ArgumentException("redirectUri 不能为空", nameof(redirectUri));
            }
            if (string.IsNullOrEmpty(codeChallenge))
            {
                throw new ArgumentException("codeChallenge 不能为空", nameof(codeChallenge));
            }

            var sb = new StringBuilder(endpoint);
            sb.Append(endpoint.IndexOf('?') >= 0 ? '&' : '?');
            sb.Append("response_type=code");
            AppendParam(sb, "client_id", clientId);
            AppendParam(sb, "redirect_uri", redirectUri);
            if (scopes != null)
            {
                string scope = string.Join(" ", scopes);
                if (scope.Length > 0)
                {
                    AppendParam(sb, "scope", scope);
                }
            }
            if (!string.IsNullOrEmpty(state))
            {
                AppendParam(sb, "state", state!);
            }
            AppendParam(sb, "code_challenge", codeChallenge);
            AppendParam(sb, "code_challenge_method", "S256");

            if (extraParams != null)
            {
                foreach (KeyValuePair<string, string> pair in extraParams)
                {
                    AppendParam(sb, pair.Key, pair.Value);
                }
            }

            return sb.ToString();
        }

        private static void AppendParam(StringBuilder sb, string name, string value)
        {
            sb.Append('&').Append(Uri.EscapeDataString(name)).Append('=').Append(Uri.EscapeDataString(value));
        }
    }
}
