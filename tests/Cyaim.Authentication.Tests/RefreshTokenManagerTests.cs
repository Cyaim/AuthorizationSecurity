using System;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Core.Tokens;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="RefreshTokenManager"/> 测试：轮换、重放检测、家族吊销。
    /// </summary>
    public class RefreshTokenManagerTests
    {
        private readonly InMemoryAuthStore _store = new InMemoryAuthStore();
        private readonly FakeClock _clock = new FakeClock();
        private readonly RefreshTokenManager _manager;

        public RefreshTokenManagerTests()
        {
            _manager = new RefreshTokenManager(
                _store, _clock,
                Options.Create(new CyaimAuthCoreOptions()),
                NullLogger<RefreshTokenManager>.Instance);
        }

        [Fact]
        public async Task 签发_记录字段正确()
        {
            (string token, RefreshTokenRecord record) = await _manager.IssueAsync(
                "u1", "app1", new[] { "openid" }, sessionId: "sess-1", lifetime: TimeSpan.FromDays(7));

            Assert.False(string.IsNullOrEmpty(token));
            Assert.Equal(TokenHasher.HashToken(token), record.TokenHash);
            Assert.Equal("u1", record.SubjectId);
            Assert.Equal("app1", record.ClientId);
            Assert.Equal("sess-1", record.SessionId);
            Assert.Equal(new[] { "openid" }, record.Scopes);
            Assert.Equal(_clock.UtcNow + TimeSpan.FromDays(7), record.ExpiresAt);
        }

        [Fact]
        public async Task 兑换成功_重放旧令牌吊销整个家族()
        {
            (string oldToken, _) = await _manager.IssueAsync("u1", "app1", new[] { "openid" });

            RefreshExchangeResult first = await _manager.ExchangeAsync(oldToken, "app1");
            Assert.True(first.Success);
            Assert.False(string.IsNullOrEmpty(first.NewToken));
            Assert.NotEqual(oldToken, first.NewToken);

            // 重放旧令牌：失败并标记重放
            RefreshExchangeResult replay = await _manager.ExchangeAsync(oldToken, "app1");
            Assert.False(replay.Success);
            Assert.Equal("invalid_grant", replay.Error);
            Assert.True(replay.ReplayDetected);

            // 家族被吊销：第一次兑换得到的新令牌同样不可用
            RefreshExchangeResult afterRevoke = await _manager.ExchangeAsync(first.NewToken!, "app1");
            Assert.False(afterRevoke.Success);
            Assert.Equal("invalid_grant", afterRevoke.Error);
        }

        [Fact]
        public async Task 客户端不匹配_失败并吊销家族()
        {
            (string token, _) = await _manager.IssueAsync("u1", "app1", Array.Empty<string>());

            RefreshExchangeResult mismatch = await _manager.ExchangeAsync(token, "evil-app");
            Assert.False(mismatch.Success);
            Assert.Equal("invalid_grant", mismatch.Error);
            Assert.True(mismatch.ReplayDetected);

            // 之后即使客户端正确也已被吊销
            RefreshExchangeResult correct = await _manager.ExchangeAsync(token, "app1");
            Assert.False(correct.Success);
        }

        [Fact]
        public async Task 过期令牌_invalid_grant()
        {
            (string token, _) = await _manager.IssueAsync(
                "u1", "app1", Array.Empty<string>(), lifetime: TimeSpan.FromHours(1));

            _clock.Advance(TimeSpan.FromHours(2));
            RefreshExchangeResult result = await _manager.ExchangeAsync(token, "app1");

            Assert.False(result.Success);
            Assert.Equal("invalid_grant", result.Error);
            Assert.Equal("刷新令牌已过期", result.ErrorDescription);
            Assert.False(result.ReplayDetected);
        }

        [Fact]
        public async Task 轮换_不延长家族绝对过期时间_且保留家族与作用域()
        {
            (string token, RefreshTokenRecord original) = await _manager.IssueAsync(
                "u1", "app1", new[] { "openid", "profile" }, lifetime: TimeSpan.FromDays(14));

            _clock.Advance(TimeSpan.FromDays(3));
            RefreshExchangeResult result = await _manager.ExchangeAsync(token, "app1");

            Assert.True(result.Success);
            Assert.Equal(original.ExpiresAt, result.Record!.ExpiresAt);
            Assert.Equal(original.FamilyId, result.Record.FamilyId);
            Assert.Equal(original.Scopes, result.Record.Scopes);
            Assert.Equal("u1", result.Record.SubjectId);
        }

        [Fact]
        public async Task 未知令牌_invalid_grant()
        {
            RefreshExchangeResult result = await _manager.ExchangeAsync("no-such-token", "app1");

            Assert.False(result.Success);
            Assert.Equal("invalid_grant", result.Error);
        }

        [Fact]
        public async Task RevokeAsync_吊销后不可兑换()
        {
            (string token, _) = await _manager.IssueAsync("u1", "app1", Array.Empty<string>());

            await _manager.RevokeAsync(token);
            RefreshExchangeResult result = await _manager.ExchangeAsync(token, "app1");

            Assert.False(result.Success);
            Assert.Equal("invalid_grant", result.Error);
        }

        [Fact]
        public async Task RevokeAllForSubject_按主体吊销()
        {
            (string t1, _) = await _manager.IssueAsync("u1", "app1", Array.Empty<string>());
            (string t2, _) = await _manager.IssueAsync("u1", "app2", Array.Empty<string>());
            (string other, _) = await _manager.IssueAsync("u2", "app1", Array.Empty<string>());

            await _manager.RevokeAllForSubjectAsync("u1");

            Assert.False((await _manager.ExchangeAsync(t1, "app1")).Success);
            Assert.False((await _manager.ExchangeAsync(t2, "app2")).Success);
            Assert.True((await _manager.ExchangeAsync(other, "app1")).Success);
        }
    }
}
