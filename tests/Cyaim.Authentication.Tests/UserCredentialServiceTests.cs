using System;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Audit;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="UserCredentialService"/> 测试：口令校验、失败计数与锁定。
    /// </summary>
    public class UserCredentialServiceTests
    {
        private const string Password = "P@ssw0rd!";

        private readonly InMemoryAuthStore _store = new InMemoryAuthStore();
        private readonly Pbkdf2PasswordHasher _hasher = new Pbkdf2PasswordHasher(1000);
        private readonly FakeClock _clock = new FakeClock();
        private readonly UserCredentialService _service;

        public UserCredentialServiceTests()
        {
            var options = new CyaimAuthCoreOptions
            {
                MaxAccessFailedCount = 3,
                LockoutDuration = TimeSpan.FromMinutes(5),
            };
            IOptions<CyaimAuthCoreOptions> wrapped = Options.Create(options);
            _service = new UserCredentialService(
                _store, _hasher, _clock,
                new DefaultAuditLogger(wrapped, NullLogger<DefaultAuditLogger>.Instance),
                wrapped,
                NullLogger<UserCredentialService>.Instance);
        }

        private async Task<AuthUser> CreateUserAsync(bool enabled = true)
        {
            var user = new AuthUser
            {
                Id = "u1",
                UserName = "alice",
                PasswordHash = _hasher.Hash(Password),
                IsEnabled = enabled,
            };
            await _store.CreateAsync(user);
            return user;
        }

        [Fact]
        public async Task 正确口令_成功并清零失败计数()
        {
            await CreateUserAsync();
            await _service.ValidateAsync("alice", "wrong"); // 先累计一次失败
            Assert.Equal(1, (await _store.FindByIdAsync("u1"))!.AccessFailedCount);

            CredentialValidationResult result = await _service.ValidateAsync("alice", Password);

            Assert.True(result.Success);
            Assert.NotNull(result.User);
            Assert.Equal("u1", result.User!.Id);
            Assert.Equal(0, (await _store.FindByIdAsync("u1"))!.AccessFailedCount);
        }

        [Fact]
        public async Task 错误口令_失败并累计计数()
        {
            await CreateUserAsync();

            CredentialValidationResult r1 = await _service.ValidateAsync("alice", "wrong1");
            CredentialValidationResult r2 = await _service.ValidateAsync("alice", "wrong2");

            Assert.False(r1.Success);
            Assert.Equal("invalid_credentials", r1.Error);
            Assert.False(r2.Success);
            Assert.Equal(2, (await _store.FindByIdAsync("u1"))!.AccessFailedCount);
        }

        [Fact]
        public async Task 达到失败上限_锁定账户()
        {
            await CreateUserAsync();

            await _service.ValidateAsync("alice", "wrong");
            await _service.ValidateAsync("alice", "wrong");
            CredentialValidationResult third = await _service.ValidateAsync("alice", "wrong");

            Assert.False(third.Success);
            AuthUser locked = (await _store.FindByIdAsync("u1"))!;
            Assert.Equal(_clock.UtcNow + TimeSpan.FromMinutes(5), locked.LockoutEnd);
            Assert.Equal(0, locked.AccessFailedCount); // 锁定后计数重置
        }

        [Fact]
        public async Task 锁定期间_正确口令也拒绝()
        {
            await CreateUserAsync();
            for (int i = 0; i < 3; i++)
            {
                await _service.ValidateAsync("alice", "wrong");
            }

            CredentialValidationResult result = await _service.ValidateAsync("alice", Password);

            Assert.False(result.Success);
            Assert.Equal("locked_out", result.Error);
        }

        [Fact]
        public async Task 锁定期过后_可正常登录()
        {
            await CreateUserAsync();
            for (int i = 0; i < 3; i++)
            {
                await _service.ValidateAsync("alice", "wrong");
            }

            _clock.Advance(TimeSpan.FromMinutes(6));
            CredentialValidationResult result = await _service.ValidateAsync("alice", Password);

            Assert.True(result.Success);
            AuthUser user = (await _store.FindByIdAsync("u1"))!;
            Assert.Null(user.LockoutEnd);
            Assert.Equal(0, user.AccessFailedCount);
        }

        [Fact]
        public async Task 禁用账户_account_disabled()
        {
            await CreateUserAsync(enabled: false);

            CredentialValidationResult result = await _service.ValidateAsync("alice", Password);

            Assert.False(result.Success);
            Assert.Equal("account_disabled", result.Error);
        }

        [Fact]
        public async Task 不存在用户_invalid_credentials()
        {
            CredentialValidationResult result = await _service.ValidateAsync("nobody", Password);

            Assert.False(result.Success);
            Assert.Equal("invalid_credentials", result.Error);
        }

        [Fact]
        public async Task 用户名不区分大小写()
        {
            await CreateUserAsync();

            Assert.True((await _service.ValidateAsync("ALICE", Password)).Success);
        }
    }
}
