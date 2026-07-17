using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// 自动附带访问令牌的 HTTP 消息处理器：
    /// 请求前通过 <see cref="CyaimAuthClient.GetAccessTokenAsync(CancellationToken)"/> 附加
    /// Authorization: Bearer；响应 401 且能刷新时刷新一次并重试。
    /// 用法：<c>new HttpClient(new CyaimAuthHttpMessageHandler(authClient) { InnerHandler = new HttpClientHandler() })</c>。
    /// </summary>
    public class CyaimAuthHttpMessageHandler : DelegatingHandler
    {
        private readonly CyaimAuthClient _client;

        /// <summary>
        /// 创建处理器（InnerHandler 需自行设置，或使用另一个构造函数）。
        /// </summary>
        /// <param name="client">提供令牌的认证客户端</param>
        public CyaimAuthHttpMessageHandler(CyaimAuthClient client)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>
        /// 创建处理器并指定内部处理器。
        /// </summary>
        /// <param name="client">提供令牌的认证客户端</param>
        /// <param name="innerHandler">内部处理器（如 HttpClientHandler）</param>
        public CyaimAuthHttpMessageHandler(CyaimAuthClient client, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <inheritdoc />
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // 请求方已显式设置 Authorization 时不覆盖
            string? attachedToken = null;
            if (request.Headers.Authorization == null && _client.IsLoggedIn)
            {
                try
                {
                    attachedToken = await _client.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", attachedToken);
                }
                catch (InvalidOperationException)
                {
                    // 无法取得有效令牌时按匿名请求发送，由服务端返回 401
                }
            }

            HttpResponseMessage response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized &&
                attachedToken != null &&
                !string.IsNullOrEmpty(_client.CurrentToken?.RefreshToken))
            {
                bool refreshed = false;
                try
                {
                    // 合并并发 401 的刷新：仅当被拒令牌仍是当前令牌时才真正刷新，
                    // 否则说明其他请求已刷新，直接用新令牌重试（避免刷新惊群与刷新令牌连环轮换）
                    refreshed = await _client.RefreshIfCurrentAsync(attachedToken, cancellationToken).ConfigureAwait(false);
                }
                catch (CyaimAuthException)
                {
                    // 刷新失败按原响应返回
                }
                catch (HttpRequestException)
                {
                    // 网络失败按原响应返回
                }

                if (refreshed)
                {
                    HttpRequestMessage retry = await CloneRequestAsync(request).ConfigureAwait(false);
                    retry.Headers.Authorization = new AuthenticationHeaderValue(
                        "Bearer",
                        await _client.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false));

                    response.Dispose();
                    response = await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
                }
            }

            return response;
        }

        /// <summary>
        /// 复制请求用于重试（HttpRequestMessage 不能重复发送；内容缓冲为字节数组后复制）。
        /// </summary>
        private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage request)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri)
            {
                Version = request.Version,
            };

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (request.Content != null)
            {
                byte[] buffer = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var content = new ByteArrayContent(buffer);
                foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
                clone.Content = content;
            }

            return clone;
        }
    }
}
