using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Stores
{
    /// <summary>
    /// 令牌存储：刷新令牌与授权码。存哈希，不存明文。
    /// </summary>
    public interface ITokenStore
    {
        /// <summary>保存刷新令牌记录</summary>
        Task SaveRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default);

        /// <summary>按哈希查找刷新令牌</summary>
        Task<RefreshTokenRecord?> FindRefreshTokenAsync(string tokenHash, CancellationToken cancellationToken = default);

        /// <summary>更新刷新令牌记录（标记消费/吊销）</summary>
        Task UpdateRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default);

        /// <summary>
        /// 原子地消费刷新令牌：仅当记录存在、未消费、未吊销且未过期时，将其标记为已消费并返回
        /// <see cref="RefreshTokenConsumeStatus.Consumed"/>；否则返回相应状态而不修改。
        /// 轮换必须经此方法完成，以在并发下保证同一令牌只能被消费一次（防止重放绕过）。
        /// </summary>
        Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);

        /// <summary>吊销令牌家族全部记录（检测到重放时调用）</summary>
        Task RevokeRefreshTokenFamilyAsync(string familyId, CancellationToken cancellationToken = default);

        /// <summary>吊销主体的全部刷新令牌（可按客户端过滤；登出/禁用用户时调用）</summary>
        Task RevokeSubjectRefreshTokensAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default);

        /// <summary>吊销某客户端签发的全部刷新令牌（删除/停用客户端时调用，避免遗留可用令牌）</summary>
        Task RevokeClientRefreshTokensAsync(string clientId, CancellationToken cancellationToken = default);

        /// <summary>保存授权码记录</summary>
        Task SaveAuthorizationCodeAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken = default);

        /// <summary>
        /// 原子地取出并标记消费授权码；不存在、已消费或已过期返回 null。
        /// 已消费的授权码被重复兑换时，实现应返回 null 且调用方需吊销相关令牌（RFC 6749 §4.1.2）。
        /// </summary>
        Task<AuthorizationCodeRecord?> ConsumeAuthorizationCodeAsync(string codeHash, CancellationToken cancellationToken = default);

        /// <summary>清理过期记录，返回清理条数</summary>
        Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// 原子消费刷新令牌的结果。
    /// </summary>
    public readonly struct RefreshTokenConsumeResult
    {
        /// <summary>消费状态</summary>
        public RefreshTokenConsumeStatus Status { get; }

        /// <summary>相关记录（NotFound 时为 null）</summary>
        public RefreshTokenRecord? Record { get; }

        /// <summary>构造结果</summary>
        public RefreshTokenConsumeResult(RefreshTokenConsumeStatus status, RefreshTokenRecord? record)
        {
            Status = status;
            Record = record;
        }
    }

    /// <summary>
    /// 刷新令牌消费状态。
    /// </summary>
    public enum RefreshTokenConsumeStatus
    {
        /// <summary>成功消费（本次调用将其从活跃转为已消费）</summary>
        Consumed = 0,
        /// <summary>令牌不存在</summary>
        NotFound = 1,
        /// <summary>已被消费（重放）</summary>
        AlreadyConsumed = 2,
        /// <summary>已被吊销</summary>
        Revoked = 3,
        /// <summary>已过期</summary>
        Expired = 4,
    }
}
