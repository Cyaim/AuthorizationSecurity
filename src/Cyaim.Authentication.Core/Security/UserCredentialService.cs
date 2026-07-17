using System;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Core.Security
{
    /// <summary>
    /// 用户凭据校验：口令验证 + 失败计数锁定 + 审计。
    /// 登录页与 password 授权共用此逻辑。
    /// </summary>
    public sealed class UserCredentialService
    {
        private readonly IUserStore _users;
        private readonly IPasswordHasher _hasher;
        private readonly IAuthClock _clock;
        private readonly IAuditLogger _audit;
        private readonly ILogger<UserCredentialService> _logger;
        private readonly CyaimAuthCoreOptions _options;
        private readonly string _dummyHash;

        /// <summary>创建服务</summary>
        public UserCredentialService(
            IUserStore users, IPasswordHasher hasher, IAuthClock clock,
            IAuditLogger audit, IOptions<CyaimAuthCoreOptions> options,
            ILogger<UserCredentialService> logger)
        {
            _users = users;
            _hasher = hasher;
            _clock = clock;
            _audit = audit;
            _options = options.Value;
            _logger = logger;
            // 用户不存在时对该假哈希执行一次等价开销的校验，抹平计时差异，防用户名枚举。
            _dummyHash = hasher.Hash("cyaim-timing-equalizer");
        }

        /// <summary>
        /// 校验用户名口令。
        /// </summary>
        public async Task<CredentialValidationResult> ValidateAsync(
            string userName, string password, string? remoteIp = null, CancellationToken cancellationToken = default)
        {
            AuthUser? user = await _users.FindByUserNameAsync(userName, cancellationToken).ConfigureAwait(false);
            DateTimeOffset now = _clock.UtcNow;

            if (user == null)
            {
                // 执行等价开销的哈希校验，使响应时间与"用户存在但口令错误"一致，消除计时侧信道。
                _hasher.Verify(_dummyHash, password);
                await AuditLoginAsync(null, userName, remoteIp, AuditOutcome.Denied, "用户不存在", cancellationToken).ConfigureAwait(false);
                return CredentialValidationResult.Fail("invalid_credentials");
            }

            if (!user.IsEnabled)
            {
                await AuditLoginAsync(user.Id, userName, remoteIp, AuditOutcome.Denied, "账户已禁用", cancellationToken).ConfigureAwait(false);
                return CredentialValidationResult.Fail("account_disabled");
            }

            if (user.IsLockedOut(now))
            {
                await AuditLoginAsync(user.Id, userName, remoteIp, AuditOutcome.Denied, "账户锁定中", cancellationToken).ConfigureAwait(false);
                return CredentialValidationResult.Fail("locked_out");
            }

            if (user.PasswordHash == null || !_hasher.Verify(user.PasswordHash, password))
            {
                user.AccessFailedCount++;
                string detail = "口令错误";
                if (user.AccessFailedCount >= _options.MaxAccessFailedCount)
                {
                    user.LockoutEnd = now + _options.LockoutDuration;
                    user.AccessFailedCount = 0;
                    detail = $"口令错误，账户锁定至 {user.LockoutEnd:u}";
                    _logger.LogWarning(AuthLogEvents.AccountLockedOut,
                        "账户 {UserName} 连续登录失败达到 {Max} 次，锁定至 {LockoutEnd}",
                        userName, _options.MaxAccessFailedCount, user.LockoutEnd);
                }
                await _users.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
                await AuditLoginAsync(user.Id, userName, remoteIp, AuditOutcome.Denied, detail, cancellationToken).ConfigureAwait(false);
                _logger.LogInformation(AuthLogEvents.LoginFailed, "登录失败 user={UserName} ip={RemoteIp}", userName, remoteIp);
                return CredentialValidationResult.Fail("invalid_credentials");
            }

            if (user.AccessFailedCount > 0 || user.LockoutEnd != null)
            {
                user.AccessFailedCount = 0;
                user.LockoutEnd = null;
                await _users.UpdateAsync(user, cancellationToken).ConfigureAwait(false);
            }

            await AuditLoginAsync(user.Id, userName, remoteIp, AuditOutcome.Success, null, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation(AuthLogEvents.LoginSucceeded, "登录成功 user={UserName} ip={RemoteIp}", userName, remoteIp);
            return CredentialValidationResult.Ok(user);
        }

        private Task AuditLoginAsync(string? subjectId, string userName, string? remoteIp, AuditOutcome outcome, string? detail, CancellationToken cancellationToken)
        {
            return _audit.WriteAsync(new AuditEvent
            {
                Category = AuditCategory.Login,
                Outcome = outcome,
                SubjectId = subjectId,
                SubjectName = userName,
                Action = "password_login",
                Detail = detail,
                RemoteIp = remoteIp,
                Timestamp = _clock.UtcNow,
            }, cancellationToken);
        }
    }

    /// <summary>
    /// 凭据校验结果。
    /// </summary>
    public sealed class CredentialValidationResult
    {
        /// <summary>是否通过</summary>
        public bool Success { get; private set; }

        /// <summary>失败原因代码（invalid_credentials / account_disabled / locked_out）</summary>
        public string? Error { get; private set; }

        /// <summary>通过时的用户</summary>
        public AuthUser? User { get; private set; }

        internal static CredentialValidationResult Ok(AuthUser user) =>
            new CredentialValidationResult { Success = true, User = user };

        internal static CredentialValidationResult Fail(string error) =>
            new CredentialValidationResult { Success = false, Error = error };
    }
}
