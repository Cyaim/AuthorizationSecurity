using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Core.Tokens
{
    /// <summary>
    /// 刷新令牌生命周期管理：签发、轮换（一次性使用）、重放检测（吊销整个家族）、吊销。
    /// 对齐 OAuth 2.0 Security BCP（RFC 9700 §4.14）的刷新令牌轮换要求。
    /// </summary>
    public sealed class RefreshTokenManager
    {
        private readonly ITokenStore _tokenStore;
        private readonly IAuthClock _clock;
        private readonly ILogger<RefreshTokenManager> _logger;
        private readonly CyaimAuthCoreOptions _options;

        /// <summary>创建管理器</summary>
        public RefreshTokenManager(
            ITokenStore tokenStore,
            IAuthClock clock,
            IOptions<CyaimAuthCoreOptions> options,
            ILogger<RefreshTokenManager> logger)
        {
            _tokenStore = tokenStore;
            _clock = clock;
            _options = options.Value;
            _logger = logger;
        }

        /// <summary>
        /// 签发新刷新令牌（新家族）。
        /// </summary>
        public async Task<(string Token, RefreshTokenRecord Record)> IssueAsync(
            string subjectId, string clientId, IEnumerable<string> scopes,
            string? sessionId = null, TimeSpan? lifetime = null, CancellationToken cancellationToken = default)
        {
            string token = TokenHasher.CreateToken();
            DateTimeOffset now = _clock.UtcNow;
            var record = new RefreshTokenRecord
            {
                TokenHash = TokenHasher.HashToken(token),
                SubjectId = subjectId,
                ClientId = clientId,
                Scopes = new List<string>(scopes),
                SessionId = sessionId,
                CreatedAt = now,
                ExpiresAt = now + (lifetime ?? _options.DefaultRefreshTokenLifetime),
            };

            await _tokenStore.SaveRefreshTokenAsync(record, cancellationToken).ConfigureAwait(false);
            return (token, record);
        }

        /// <summary>
        /// 兑换刷新令牌：校验并轮换（旧令牌标记消费，签发同家族新令牌）。
        /// 检测到已消费令牌被重放时吊销整个家族。
        /// </summary>
        public async Task<RefreshExchangeResult> ExchangeAsync(string refreshToken, string clientId, CancellationToken cancellationToken = default)
        {
            RefreshTokenRecord? record = await _tokenStore.FindRefreshTokenAsync(TokenHasher.HashToken(refreshToken), cancellationToken).ConfigureAwait(false);
            if (record == null)
            {
                return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌无效");
            }

            DateTimeOffset now = _clock.UtcNow;

            if (!string.Equals(record.ClientId, clientId, StringComparison.Ordinal))
            {
                // 令牌被其他客户端使用：按泄露处理
                await _tokenStore.RevokeRefreshTokenFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
                _logger.LogWarning(AuthLogEvents.RefreshTokenReplay,
                    "刷新令牌客户端不匹配 expected={Expected} actual={Actual}，家族 {FamilyId} 已吊销", record.ClientId, clientId, record.FamilyId);
                return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌无效", replayDetected: true);
            }

            // 原子消费（check-then-set 在存储层单次操作内完成，杜绝并发下同一令牌被消费两次）
            RefreshTokenConsumeResult consume = await _tokenStore
                .ConsumeRefreshTokenAsync(record.TokenHash, now, cancellationToken).ConfigureAwait(false);

            switch (consume.Status)
            {
                case RefreshTokenConsumeStatus.Consumed:
                    break;

                case RefreshTokenConsumeStatus.AlreadyConsumed:
                    // 重放（或并发的另一次兑换已抢先消费）：吊销家族（RFC 9700 §4.14.2）
                    await _tokenStore.RevokeRefreshTokenFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
                    _logger.LogWarning(AuthLogEvents.RefreshTokenReplay,
                        "检测到刷新令牌重放 subject={SubjectId} client={ClientId}，家族 {FamilyId} 已吊销",
                        record.SubjectId, record.ClientId, record.FamilyId);
                    return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌无效", replayDetected: true);

                case RefreshTokenConsumeStatus.Revoked:
                    return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌已吊销");

                case RefreshTokenConsumeStatus.Expired:
                    return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌已过期");

                default: // NotFound（并发删除等）
                    return RefreshExchangeResult.Fail("invalid_grant", "刷新令牌无效");
            }

            string newToken = TokenHasher.CreateToken();
            var newRecord = new RefreshTokenRecord
            {
                TokenHash = TokenHasher.HashToken(newToken),
                FamilyId = record.FamilyId,
                SubjectId = record.SubjectId,
                ClientId = record.ClientId,
                Scopes = new List<string>(record.Scopes),
                SessionId = record.SessionId,
                CreatedAt = now,
                ExpiresAt = record.ExpiresAt, // 家族绝对过期时间不因轮换延长
            };
            await _tokenStore.SaveRefreshTokenAsync(newRecord, cancellationToken).ConfigureAwait(false);

            return RefreshExchangeResult.Ok(newToken, newRecord);
        }

        /// <summary>
        /// 吊销刷新令牌所在家族（RFC 7009）。令牌不存在时静默成功。
        /// </summary>
        public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            RefreshTokenRecord? record = await _tokenStore.FindRefreshTokenAsync(TokenHasher.HashToken(refreshToken), cancellationToken).ConfigureAwait(false);
            if (record != null)
            {
                await _tokenStore.RevokeRefreshTokenFamilyAsync(record.FamilyId, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// 吊销主体的全部刷新令牌（登出、禁用账户时调用）。
        /// </summary>
        public Task RevokeAllForSubjectAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default) =>
            _tokenStore.RevokeSubjectRefreshTokensAsync(subjectId, clientId, cancellationToken);
    }

    /// <summary>
    /// 刷新令牌兑换结果。
    /// </summary>
    public sealed class RefreshExchangeResult
    {
        /// <summary>是否成功</summary>
        public bool Success { get; private set; }

        /// <summary>OAuth 错误码（invalid_grant 等）</summary>
        public string? Error { get; private set; }

        /// <summary>错误描述</summary>
        public string? ErrorDescription { get; private set; }

        /// <summary>是否检测到重放</summary>
        public bool ReplayDetected { get; private set; }

        /// <summary>新刷新令牌明文</summary>
        public string? NewToken { get; private set; }

        /// <summary>新刷新令牌记录</summary>
        public RefreshTokenRecord? Record { get; private set; }

        internal static RefreshExchangeResult Ok(string newToken, RefreshTokenRecord record) =>
            new RefreshExchangeResult { Success = true, NewToken = newToken, Record = record };

        internal static RefreshExchangeResult Fail(string error, string description, bool replayDetected = false) =>
            new RefreshExchangeResult { Success = false, Error = error, ErrorDescription = description, ReplayDetected = replayDetected };
    }
}
