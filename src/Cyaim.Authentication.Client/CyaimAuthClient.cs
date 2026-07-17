using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;

namespace Cyaim.Authentication.Client
{
    /// <summary>
    /// Cyaim.Authentication 客户端：登录（密码 / 客户端凭据 / 授权码+PKCE）、自动刷新、
    /// 令牌缓存恢复、本地权限检查。线程安全，可跨 WinForms/WPF/WASM/控制台/服务复用同一实例。
    /// </summary>
    public class CyaimAuthClient : IDisposable
    {
        private static readonly JsonSerializerOptions s_jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };

        private readonly CyaimAuthClientOptions _options;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly ITokenCache? _cache;
        private readonly IAuthClock _clock;
        private readonly SemaphoreSlim _gate = new SemaphoreSlim(1, 1);
        private readonly SemaphoreSlim _discoveryGate = new SemaphoreSlim(1, 1);
        private readonly string _authority;

        private volatile TokenSet? _token;
        private volatile DiscoveryDocument? _discovery;
        private volatile CompiledPermissionSet? _permissions;
        private bool _disposed;

        private enum RefreshOutcome
        {
            /// <summary>无刷新令牌，无法刷新</summary>
            NoRefreshToken,
            /// <summary>刷新成功</summary>
            Success,
            /// <summary>刷新令牌被服务器拒绝（invalid_grant），会话已过期</summary>
            SessionExpired,
        }

        /// <summary>
        /// 创建客户端。
        /// </summary>
        /// <param name="options">客户端配置（Authority 必填）</param>
        /// <param name="httpClient">HTTP 客户端（不传则内部自建并随 Dispose 释放；SDK 全部使用绝对 URL，不依赖 BaseAddress）</param>
        /// <param name="cache">令牌缓存（传入时构造即尝试恢复上次会话）</param>
        /// <param name="clock">时钟（默认系统时钟，测试可注入）</param>
        public CyaimAuthClient(
            CyaimAuthClientOptions options,
            HttpClient? httpClient = null,
            ITokenCache? cache = null,
            IAuthClock? clock = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (string.IsNullOrEmpty(options.Authority))
            {
                throw new ArgumentException("CyaimAuthClientOptions.Authority 不能为空", nameof(options));
            }

            _authority = options.Authority.TrimEnd('/');
            _ownsHttp = httpClient == null;
            _http = httpClient ?? new HttpClient();
            _cache = cache;
            _clock = clock ?? new SystemClock();

            // 从缓存恢复会话（重启免登录）
            _token = cache?.Load();
        }

        /// <summary>当前令牌（未登录为 null）</summary>
        public TokenSet? CurrentToken => _token;

        /// <summary>是否已登录（持有令牌，不保证未过期）</summary>
        public bool IsLoggedIn => _token != null;

        /// <summary>已加载的授予权限代码列表（未调用 LoadPermissions 前为 null）</summary>
        public IReadOnlyList<string>? GrantedPermissions => _permissions?.Allows;

        /// <summary>令牌变更（登录、刷新、登出）时触发</summary>
        public event EventHandler? TokenChanged;

        /// <summary>会话过期（刷新令牌被服务器拒绝）时触发，应引导用户重新登录</summary>
        public event EventHandler? SessionExpired;

        #region 发现文档

        /// <summary>
        /// 获取发现文档（首次请求后缓存）。请求失败时回退到框架默认端点布局（/connect/token 等）。
        /// </summary>
        public async Task<DiscoveryDocument> DiscoverAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            DiscoveryDocument? discovery = _discovery;
            if (discovery != null)
            {
                return discovery;
            }

            await _discoveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_discovery != null)
                {
                    return _discovery;
                }

                string url = ResolveEndpoint(_options.DiscoveryPath, AuthConstants.Endpoints.Discovery);
                DiscoveryDocument? fetched = null;
                try
                {
                    using (var request = new HttpRequestMessage(HttpMethod.Get, url))
                    using (HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false))
                    {
                        if (response.IsSuccessStatusCode)
                        {
                            string json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                            fetched = JsonSerializer.Deserialize<DiscoveryDocument>(json, s_jsonOptions);
                        }
                    }
                }
                catch (HttpRequestException)
                {
                    // 网络失败回退默认布局
                }
                catch (JsonException)
                {
                    // 响应不是合法 JSON 回退默认布局
                }

                _discovery = fetched ?? CreateFallbackDiscovery();
                return _discovery;
            }
            finally
            {
                _discoveryGate.Release();
            }
        }

        private DiscoveryDocument CreateFallbackDiscovery()
        {
            return new DiscoveryDocument
            {
                Issuer = _authority,
                TokenEndpoint = _authority + AuthConstants.Endpoints.Token,
                AuthorizationEndpoint = _authority + AuthConstants.Endpoints.Authorize,
                UserInfoEndpoint = _authority + AuthConstants.Endpoints.UserInfo,
                RevocationEndpoint = _authority + AuthConstants.Endpoints.Revoke,
                IntrospectionEndpoint = _authority + AuthConstants.Endpoints.Introspect,
                JwksUri = _authority + AuthConstants.Endpoints.Jwks,
                EndSessionEndpoint = _authority + AuthConstants.Endpoints.EndSession,
            };
        }

        /// <summary>
        /// 将发现文档中的端点（可能为绝对 URL / 相对路径 / 缺失）解析为绝对 URL。
        /// </summary>
        private string ResolveEndpoint(string? endpoint, string fallbackPath)
        {
            if (string.IsNullOrEmpty(endpoint))
            {
                return _authority + fallbackPath;
            }

            if (endpoint!.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                endpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return endpoint;
            }

            return endpoint[0] == '/' ? _authority + endpoint : _authority + "/" + endpoint;
        }

        #endregion

        #region 登录 / 刷新 / 登出

        /// <summary>
        /// 资源所有者密码模式登录 (grant_type=password)。
        /// </summary>
        public async Task LoginWithPasswordAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            if (userName == null) throw new ArgumentNullException(nameof(userName));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = AuthConstants.GrantTypes.Password,
                ["username"] = userName,
                ["password"] = password,
                ["scope"] = string.Join(" ", _options.Scopes),
            };
            await LoginCoreAsync(form, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 客户端凭据模式登录 (grant_type=client_credentials)，适合服务对服务调用。
        /// </summary>
        public async Task LoginWithClientCredentialsAsync(CancellationToken cancellationToken = default)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = AuthConstants.GrantTypes.ClientCredentials,
                ["scope"] = string.Join(" ", _options.Scopes),
            };
            await LoginCoreAsync(form, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 用授权码换取令牌 (grant_type=authorization_code + PKCE)。
        /// 配合 <see cref="Pkce.BuildAuthorizeUrl(string, string, string, System.Collections.Generic.IEnumerable{string}, string, string, System.Collections.Generic.IDictionary{string, string})"/> 使用。
        /// </summary>
        /// <param name="code">授权码（回调 URL 中的 code 参数）</param>
        /// <param name="redirectUri">与授权请求一致的回调地址</param>
        /// <param name="codeVerifier">授权请求时生成的 PKCE code_verifier</param>
        /// <param name="cancellationToken">取消令牌</param>
        public async Task ExchangeAuthorizationCodeAsync(string code, string redirectUri, string codeVerifier, CancellationToken cancellationToken = default)
        {
            if (code == null) throw new ArgumentNullException(nameof(code));
            if (redirectUri == null) throw new ArgumentNullException(nameof(redirectUri));
            if (codeVerifier == null) throw new ArgumentNullException(nameof(codeVerifier));

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = AuthConstants.GrantTypes.AuthorizationCode,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = codeVerifier,
            };
            await LoginCoreAsync(form, cancellationToken).ConfigureAwait(false);
        }

        private async Task LoginCoreAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await RequestTokenAsync(form, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }

            TokenChanged?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// 用刷新令牌换新令牌。无刷新令牌返回 false；
        /// 刷新令牌被拒绝 (invalid_grant) 时清空本地令牌、触发 <see cref="SessionExpired"/> 并返回 false。
        /// </summary>
        public async Task<bool> RefreshAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            RefreshOutcome outcome;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                outcome = await RefreshCoreAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _gate.Release();
            }

            RaiseRefreshEvents(outcome);
            return outcome == RefreshOutcome.Success;
        }

        /// <summary>
        /// 仅当当前访问令牌仍是 <paramref name="rejectedAccessToken"/> 时才刷新；若已被其他线程刷新
        /// 则直接返回 true（调用方应改用新令牌重试，无需再刷新）。用于合并并发 401 的刷新惊群。
        /// </summary>
        /// <param name="rejectedAccessToken">本次请求发出的、被服务端拒绝的访问令牌</param>
        /// <param name="cancellationToken">取消令牌</param>
        /// <returns>存在可用的新令牌（已刷新或已被他人刷新）返回 true</returns>
        public async Task<bool> RefreshIfCurrentAsync(string rejectedAccessToken, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            RefreshOutcome? outcome = null;
            bool tokenAlreadyRotated = false;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // 其他并发请求已刷新：当前令牌已不是被拒的那个，直接用新令牌重试
                if (!string.Equals(_token?.AccessToken, rejectedAccessToken, StringComparison.Ordinal))
                {
                    tokenAlreadyRotated = _token != null;
                }
                else
                {
                    outcome = await RefreshCoreAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _gate.Release();
            }

            if (outcome.HasValue)
            {
                RaiseRefreshEvents(outcome.Value);
                return outcome.Value == RefreshOutcome.Success;
            }
            return tokenAlreadyRotated;
        }

        /// <summary>刷新逻辑（须在持有 _gate 时调用；事件由调用方在释放锁后触发）</summary>
        private async Task<RefreshOutcome> RefreshCoreAsync(CancellationToken cancellationToken)
        {
            string? refreshToken = _token?.RefreshToken;
            if (string.IsNullOrEmpty(refreshToken))
            {
                return RefreshOutcome.NoRefreshToken;
            }

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = AuthConstants.GrantTypes.RefreshToken,
                ["refresh_token"] = refreshToken!,
            };

            try
            {
                await RequestTokenAsync(form, cancellationToken).ConfigureAwait(false);
                return RefreshOutcome.Success;
            }
            catch (CyaimAuthException ex) when (ex.Error == "invalid_grant")
            {
                ClearTokenCore();
                return RefreshOutcome.SessionExpired;
            }
        }

        private void RaiseRefreshEvents(RefreshOutcome outcome)
        {
            switch (outcome)
            {
                case RefreshOutcome.Success:
                    TokenChanged?.Invoke(this, EventArgs.Empty);
                    break;
                case RefreshOutcome.SessionExpired:
                    TokenChanged?.Invoke(this, EventArgs.Empty);
                    SessionExpired?.Invoke(this, EventArgs.Empty);
                    break;
            }
        }

        /// <summary>
        /// 获取有效访问令牌（核心入口）：未过期直接返回；过期且开启 AutoRefresh 则先刷新。
        /// </summary>
        /// <exception cref="InvalidOperationException">未登录，或令牌过期且无法自动刷新</exception>
        public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            // 无锁快路径：令牌有效时直接返回，不进信号量（_token 为 volatile，引用读取原子）。
            // 令牌绝大多数请求都有效，避免不必要的锁争用。
            TokenSet? fast = _token;
            if (fast != null && !IsExpired(fast))
            {
                return fast.AccessToken;
            }

            string? result = null;
            RefreshOutcome? outcome = null;

            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                TokenSet? token = _token;
                if (token == null)
                {
                    throw new InvalidOperationException("未登录");
                }

                if (!IsExpired(token))
                {
                    return token.AccessToken;
                }

                if (_options.AutoRefresh)
                {
                    outcome = await RefreshCoreAsync(cancellationToken).ConfigureAwait(false);
                    if (outcome == RefreshOutcome.Success)
                    {
                        result = _token?.AccessToken;
                    }
                }
            }
            finally
            {
                _gate.Release();
            }

            if (outcome.HasValue)
            {
                RaiseRefreshEvents(outcome.Value);
            }

            if (result != null)
            {
                return result;
            }

            if (outcome == RefreshOutcome.SessionExpired)
            {
                throw new InvalidOperationException("登录会话已过期，请重新登录");
            }

            throw new InvalidOperationException("访问令牌已过期且无法自动刷新，请重新登录");
        }

        /// <summary>
        /// 登出：有吊销端点且持有刷新令牌时向服务器吊销（尽力而为），随后清空本地令牌与缓存。
        /// </summary>
        public async Task LogoutAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            bool hadToken;
            await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                hadToken = _token != null;
                string? refreshToken = _token?.RefreshToken;
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    try
                    {
                        DiscoveryDocument discovery = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
                        if (!string.IsNullOrEmpty(discovery.RevocationEndpoint))
                        {
                            string url = ResolveEndpoint(discovery.RevocationEndpoint, AuthConstants.Endpoints.Revoke);
                            var form = new Dictionary<string, string>
                            {
                                ["token"] = refreshToken!,
                                ["token_type_hint"] = "refresh_token",
                            };
                            AppendClientCredentials(form);
                            using (var request = new HttpRequestMessage(HttpMethod.Post, url)
                            {
                                Content = new FormUrlEncodedContent(form),
                            })
                            using (await _http.SendAsync(request, cancellationToken).ConfigureAwait(false))
                            {
                                // 吊销失败不阻断登出
                            }
                        }
                    }
                    catch (HttpRequestException)
                    {
                        // 网络失败仍然完成本地登出
                    }
                }

                ClearTokenCore();
            }
            finally
            {
                _gate.Release();
            }

            if (hadToken)
            {
                TokenChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        /// <summary>清空本地令牌与缓存（须在持有 _gate 时调用）</summary>
        private void ClearTokenCore()
        {
            _token = null;
            _permissions = null;
            _cache?.Save(null);
        }

        private bool IsExpired(TokenSet token)
        {
            return _clock.UtcNow >= token.ExpiresAt - _options.RefreshSkew;
        }

        #endregion

        #region 令牌端点

        /// <summary>
        /// 调用令牌端点并存储结果（须在持有 _gate 时调用）。
        /// </summary>
        private async Task RequestTokenAsync(Dictionary<string, string> form, CancellationToken cancellationToken)
        {
            DiscoveryDocument discovery = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
            string url = ResolveEndpoint(discovery.TokenEndpoint, AuthConstants.Endpoints.Token);
            AppendClientCredentials(form);

            string body;
            bool success;
            using (var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new FormUrlEncodedContent(form),
            })
            using (HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false))
            {
                success = response.IsSuccessStatusCode;
                body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (!success)
                {
                    throw CreateProtocolException(body, (int)response.StatusCode);
                }
            }

            TokenResponse? tokenResponse;
            try
            {
                tokenResponse = JsonSerializer.Deserialize<TokenResponse>(body, s_jsonOptions);
            }
            catch (JsonException)
            {
                tokenResponse = null;
            }

            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                throw new CyaimAuthException("invalid_response", "令牌端点未返回 access_token");
            }

            string[]? scopes = null;
            if (!string.IsNullOrEmpty(tokenResponse.Scope))
            {
                scopes = tokenResponse.Scope!.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            }

            var tokenSet = new TokenSet
            {
                AccessToken = tokenResponse.AccessToken!,
                // 刷新令牌轮换：服务器未返回新刷新令牌时沿用旧的
                RefreshToken = string.IsNullOrEmpty(tokenResponse.RefreshToken) ? _token?.RefreshToken : tokenResponse.RefreshToken,
                ExpiresAt = _clock.UtcNow.AddSeconds(tokenResponse.ExpiresIn > 0 ? tokenResponse.ExpiresIn : 300),
                Scopes = scopes ?? _token?.Scopes,
            };

            _token = tokenSet;
            _cache?.Save(tokenSet);
        }

        private void AppendClientCredentials(Dictionary<string, string> form)
        {
            if (!form.ContainsKey("client_id") && !string.IsNullOrEmpty(_options.ClientId))
            {
                form["client_id"] = _options.ClientId;
            }
            if (!form.ContainsKey("client_secret") && !string.IsNullOrEmpty(_options.ClientSecret))
            {
                form["client_secret"] = _options.ClientSecret!;
            }
        }

        private static CyaimAuthException CreateProtocolException(string body, int statusCode)
        {
            TokenErrorResponse? error = null;
            try
            {
                error = JsonSerializer.Deserialize<TokenErrorResponse>(body, s_jsonOptions);
            }
            catch (JsonException)
            {
                // 非 JSON 响应
            }

            if (error != null && !string.IsNullOrEmpty(error.Error))
            {
                return new CyaimAuthException(error.Error!, error.ErrorDescription);
            }

            return new CyaimAuthException("http_" + statusCode, string.IsNullOrEmpty(body) ? null : body);
        }

        #endregion

        #region 用户信息 / 权限

        /// <summary>
        /// 调用 UserInfo 端点获取当前主体信息（自动附带访问令牌）。
        /// </summary>
        public async Task<UserInfoResponse> GetUserInfoAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            string accessToken = await GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            DiscoveryDocument discovery = await DiscoverAsync(cancellationToken).ConfigureAwait(false);
            string url = ResolveEndpoint(discovery.UserInfoEndpoint, AuthConstants.Endpoints.UserInfo);

            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                using (HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false))
                {
                    string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw CreateProtocolException(body, (int)response.StatusCode);
                    }

                    UserInfoResponse? userInfo;
                    try
                    {
                        userInfo = JsonSerializer.Deserialize<UserInfoResponse>(body, s_jsonOptions);
                    }
                    catch (JsonException)
                    {
                        userInfo = null;
                    }

                    if (userInfo == null)
                    {
                        throw new CyaimAuthException("invalid_response", "UserInfo 端点返回了无法解析的响应");
                    }

                    return userInfo;
                }
            }
        }

        /// <summary>
        /// 从 UserInfo 端点加载权限（permissions 数组）并编译为本地权限集，之后可用
        /// <see cref="HasPermission(string)"/> 离线检查（支持通配符与拒绝优先语义）。
        /// </summary>
        public async Task LoadPermissionsAsync(CancellationToken cancellationToken = default)
        {
            UserInfoResponse userInfo = await GetUserInfoAsync(cancellationToken).ConfigureAwait(false);
            _permissions = CompiledPermissionSet.Build(userInfo.Permissions ?? Array.Empty<string>());
        }

        /// <summary>
        /// 从当前访问令牌本地解析权限（读取 JWT payload 的 perm 声明，不验签、不联网），离线可用。
        /// 需要令牌签发时启用 IncludePermissionsInToken。
        /// </summary>
        /// <returns>解析成功返回 true；无令牌、非 JWT 或无 perm 声明返回 false</returns>
        public bool LoadPermissionsFromToken()
        {
            string? accessToken = _token?.AccessToken;
            if (string.IsNullOrEmpty(accessToken))
            {
                return false;
            }

            try
            {
                string[] parts = accessToken!.Split('.');
                if (parts.Length != 3)
                {
                    return false;
                }

                byte[] payload = Base64Url.Decode(parts[1]);
                using (JsonDocument document = JsonDocument.Parse(payload))
                {
                    if (!document.RootElement.TryGetProperty(AuthConstants.ClaimTypes.Permission, out JsonElement permElement))
                    {
                        return false;
                    }

                    var codes = new List<string>();
                    if (permElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (JsonElement item in permElement.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.String)
                            {
                                string? value = item.GetString();
                                if (value != null)
                                {
                                    codes.Add(value);
                                }
                            }
                        }
                    }
                    else if (permElement.ValueKind == JsonValueKind.String)
                    {
                        string? value = permElement.GetString();
                        if (value != null)
                        {
                            codes.Add(value);
                        }
                    }
                    else
                    {
                        return false;
                    }

                    _permissions = CompiledPermissionSet.Build(codes);
                    return true;
                }
            }
            catch (FormatException)
            {
                return false;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        /// <summary>
        /// 本地检查权限（需先调用 <see cref="LoadPermissionsAsync(CancellationToken)"/> 或
        /// <see cref="LoadPermissionsFromToken"/>；未加载时返回 false）。
        /// </summary>
        public bool HasPermission(string code)
        {
            CompiledPermissionSet? permissions = _permissions;
            return permissions != null && permissions.IsGranted(code);
        }

        #endregion

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(CyaimAuthClient));
            }
        }

        /// <summary>
        /// 释放内部资源（自建的 HttpClient 一并释放；外部传入的不释放）。
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>释放资源</summary>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;

            if (disposing)
            {
                if (_ownsHttp)
                {
                    _http.Dispose();
                }
                _gate.Dispose();
                _discoveryGate.Dispose();
            }
        }

        /// <summary>默认系统时钟</summary>
        private sealed class SystemClock : IAuthClock
        {
            public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
        }
    }
}
