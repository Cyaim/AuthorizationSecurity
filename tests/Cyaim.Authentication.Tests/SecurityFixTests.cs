using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Audit;
using Cyaim.Authentication.Core.Security;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Core.Tokens;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// 安全修复回归测试：
    /// 1. <see cref="ITokenStore.ConsumeRefreshTokenAsync"/> 原子消费（防并发重放绕过）；
    /// 2. <see cref="RefreshTokenManager.ExchangeAsync"/> 经原子路径轮换、重放检测与家族吊销；
    /// 3. 安全戳（sstamp）失效：口令重置/授权变更后旧访问令牌在下次权限判断时被判定 SubjectDisabled；
    /// 4. <see cref="UserCredentialService"/> 用户不存在时的假哈希校验（计时侧信道防护，功能不回归）；
    /// 5. <see cref="JsonFileAuthStore"/> 后台落盘异常安全（吞掉 IO 异常并记录 LastSaveError，不崩溃进程）。
    /// </summary>
    public class SecurityFixTests
    {
        // ---------------------------------------------------------------- 原子消费（ITokenStore.ConsumeRefreshTokenAsync）

        /// <summary>创建一条活跃刷新令牌记录并保存。</summary>
        private static async Task<RefreshTokenRecord> SaveActiveRecordAsync(
            InMemoryAuthStore store, FakeClock clock, string tokenHash,
            DateTimeOffset? revokedAt = null, TimeSpan? lifetime = null)
        {
            var record = new RefreshTokenRecord
            {
                TokenHash = tokenHash,
                SubjectId = "u1",
                ClientId = "app1",
                CreatedAt = clock.UtcNow,
                ExpiresAt = clock.UtcNow + (lifetime ?? TimeSpan.FromDays(7)),
                RevokedAt = revokedAt,
            };
            await store.SaveRefreshTokenAsync(record);
            return record;
        }

        [Fact]
        public async Task 原子消费_活跃令牌首次Consumed_再次AlreadyConsumed()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();
            await SaveActiveRecordAsync(store, clock, "h1");

            // 首次消费：活跃 → 已消费，返回 Consumed 且记录携带消费时间
            RefreshTokenConsumeResult first = await store.ConsumeRefreshTokenAsync("h1", clock.UtcNow);
            Assert.Equal(RefreshTokenConsumeStatus.Consumed, first.Status);
            Assert.NotNull(first.Record);
            Assert.Equal(clock.UtcNow, first.Record!.ConsumedAt);

            // 再次消费同一哈希：重放，返回 AlreadyConsumed 且不改写状态
            RefreshTokenConsumeResult second = await store.ConsumeRefreshTokenAsync("h1", clock.UtcNow);
            Assert.Equal(RefreshTokenConsumeStatus.AlreadyConsumed, second.Status);
            Assert.NotNull(second.Record);
        }

        [Fact]
        public async Task 原子消费_已吊销令牌返回Revoked_且不标记消费()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();
            await SaveActiveRecordAsync(store, clock, "h-revoked", revokedAt: clock.UtcNow);

            RefreshTokenConsumeResult result = await store.ConsumeRefreshTokenAsync("h-revoked", clock.UtcNow);

            Assert.Equal(RefreshTokenConsumeStatus.Revoked, result.Status);
            Assert.NotNull(result.Record);
            // 已吊销记录不应被标记消费
            RefreshTokenRecord? stored = await store.FindRefreshTokenAsync("h-revoked");
            Assert.Null(stored!.ConsumedAt);
        }

        [Fact]
        public async Task 原子消费_过期令牌返回Expired_且不标记消费()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();
            await SaveActiveRecordAsync(store, clock, "h-expired", lifetime: TimeSpan.FromHours(1));

            // 推进时钟越过过期时间
            clock.Advance(TimeSpan.FromHours(2));
            RefreshTokenConsumeResult result = await store.ConsumeRefreshTokenAsync("h-expired", clock.UtcNow);

            Assert.Equal(RefreshTokenConsumeStatus.Expired, result.Status);
            Assert.NotNull(result.Record);
            RefreshTokenRecord? stored = await store.FindRefreshTokenAsync("h-expired");
            Assert.Null(stored!.ConsumedAt);
        }

        [Fact]
        public async Task 原子消费_不存在的哈希返回NotFound()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();

            RefreshTokenConsumeResult result = await store.ConsumeRefreshTokenAsync("no-such-hash", clock.UtcNow);

            Assert.Equal(RefreshTokenConsumeStatus.NotFound, result.Status);
            Assert.Null(result.Record);
        }

        [Fact]
        public async Task 原子消费_并发争抢同一令牌_只有一次Consumed()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();
            await SaveActiveRecordAsync(store, clock, "h-race");

            // 32 个并发任务同时消费同一令牌：锁内 check-then-set 保证恰好一次成功
            var gate = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
            Task<RefreshTokenConsumeResult>[] tasks = Enumerable.Range(0, 32)
                .Select(_ => Task.Run(async () =>
                {
                    await gate.Task;
                    return await store.ConsumeRefreshTokenAsync("h-race", clock.UtcNow);
                }))
                .ToArray();
            gate.SetResult(null);
            RefreshTokenConsumeResult[] results = await Task.WhenAll(tasks);

            Assert.Equal(1, results.Count(r => r.Status == RefreshTokenConsumeStatus.Consumed));
            Assert.Equal(31, results.Count(r => r.Status == RefreshTokenConsumeStatus.AlreadyConsumed));
        }

        // ---------------------------------------------------------------- RefreshTokenManager 经原子路径轮换

        [Fact]
        public async Task 刷新令牌管理器_原子路径_兑换成功_重放吊销家族_新令牌失效()
        {
            var store = new InMemoryAuthStore();
            var clock = new FakeClock();
            var manager = new RefreshTokenManager(
                store, clock,
                Options.Create(new CyaimAuthCoreOptions()),
                NullLogger<RefreshTokenManager>.Instance);

            (string oldToken, RefreshTokenRecord oldRecord) =
                await manager.IssueAsync("u1", "app1", new[] { "openid" });

            // 兑换成功：底层经 ConsumeRefreshTokenAsync 将旧记录原子标记消费
            RefreshExchangeResult first = await manager.ExchangeAsync(oldToken, "app1");
            Assert.True(first.Success);
            Assert.False(string.IsNullOrEmpty(first.NewToken));
            RefreshTokenRecord? consumed = await store.FindRefreshTokenAsync(oldRecord.TokenHash);
            Assert.NotNull(consumed!.ConsumedAt);

            // 直接从存储层验证：旧哈希再消费即 AlreadyConsumed
            RefreshTokenConsumeResult replayConsume =
                await store.ConsumeRefreshTokenAsync(oldRecord.TokenHash, clock.UtcNow);
            Assert.Equal(RefreshTokenConsumeStatus.AlreadyConsumed, replayConsume.Status);

            // 经管理器重放旧令牌：invalid_grant + 重放标记 + 吊销家族
            RefreshExchangeResult replay = await manager.ExchangeAsync(oldToken, "app1");
            Assert.False(replay.Success);
            Assert.Equal("invalid_grant", replay.Error);
            Assert.True(replay.ReplayDetected);

            // 家族已吊销：第一次兑换得到的新令牌同样不可用
            RefreshExchangeResult afterRevoke = await manager.ExchangeAsync(first.NewToken!, "app1");
            Assert.False(afterRevoke.Success);
            Assert.Equal("invalid_grant", afterRevoke.Error);

            // 新令牌记录的存储层状态为 Revoked（家族吊销的直接证据）
            RefreshTokenConsumeResult revoked =
                await store.ConsumeRefreshTokenAsync(first.Record!.TokenHash, clock.UtcNow);
            Assert.Equal(RefreshTokenConsumeStatus.Revoked, revoked.Status);
        }

        // ---------------------------------------------------------------- 安全戳失效（PermissionEvaluator.BuildEntryAsync）

        /// <summary>构造携带指定 sstamp 声明的用户主体（stamp 为 null 表示令牌不含 sstamp）。</summary>
        private static AuthSubject SubjectWithStamp(string id, string? stamp)
        {
            var claims = new Dictionary<string, string>(StringComparer.Ordinal);
            if (stamp != null)
            {
                claims[AuthConstants.ClaimTypes.SecurityStamp] = stamp;
            }
            return new AuthSubject
            {
                Id = id,
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.User,
                Claims = claims,
            };
        }

        [Fact]
        public async Task 安全戳_轮换后旧sstamp令牌SubjectDisabled_新sstamp正常授权()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();

            var user = new AuthUser { Id = "u1", UserName = "alice" };
            user.DirectPermissions.Add("doc.read");
            await store.CreateAsync(user);
            string oldStamp = user.SecurityStamp;

            // 轮换前：携带当前安全戳的令牌正常授权
            AuthorizationDecision before = await evaluator.EvaluateAsync(SubjectWithStamp("u1", oldStamp), "doc.read");
            Assert.True(before.IsGranted);

            // 模拟口令重置/授权变更：轮换安全戳（UpdateAsync 内部 Bump 版本号，评估器缓存随之失效）
            AuthUser updated = (await store.FindByIdAsync("u1"))!;
            updated.SecurityStamp = Guid.NewGuid().ToString("N");
            await store.UpdateAsync(updated);

            // 携带旧 sstamp 的令牌：判定主体禁用（旧访问令牌立即失效）
            AuthorizationDecision stale = await evaluator.EvaluateAsync(SubjectWithStamp("u1", oldStamp), "doc.read");
            Assert.False(stale.IsGranted);
            Assert.Equal(AuthorizationReason.SubjectDisabled, stale.Reason);

            // 携带当前 sstamp 的令牌（重新登录后签发）：仍正常授权
            AuthorizationDecision fresh = await evaluator.EvaluateAsync(SubjectWithStamp("u1", updated.SecurityStamp), "doc.read");
            Assert.True(fresh.IsGranted);
        }

        [Fact]
        public async Task 安全戳_令牌不含sstamp声明_轮换不影响授权()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();

            var user = new AuthUser { Id = "u1", UserName = "alice" };
            user.DirectPermissions.Add("doc.read");
            await store.CreateAsync(user);

            AuthUser updated = (await store.FindByIdAsync("u1"))!;
            updated.SecurityStamp = Guid.NewGuid().ToString("N");
            await store.UpdateAsync(updated);

            // 无 sstamp 声明的令牌（旧版本签发或外部签发）不参与安全戳比对，仍按存储数据授权
            AuthorizationDecision decision = await evaluator.EvaluateAsync(SubjectWithStamp("u1", null), "doc.read");
            Assert.True(decision.IsGranted);
        }

        // ---------------------------------------------------------------- 假哈希计时（UserCredentialService）

        [Fact]
        public async Task 假哈希计时_不存在用户与口令错误_返回相同错误码()
        {
            var store = new InMemoryAuthStore();
            var hasher = new Pbkdf2PasswordHasher(1000);
            var clock = new FakeClock();
            IOptions<CyaimAuthCoreOptions> options = Options.Create(new CyaimAuthCoreOptions());
            var service = new UserCredentialService(
                store, hasher, clock,
                new DefaultAuditLogger(options, NullLogger<DefaultAuditLogger>.Instance),
                options,
                NullLogger<UserCredentialService>.Instance);

            await store.CreateAsync(new AuthUser
            {
                Id = "u1",
                UserName = "alice",
                PasswordHash = hasher.Hash("P@ssw0rd!"),
            });

            // 用户不存在：内部对假哈希执行等价开销的 Verify，功能上仍返回 invalid_credentials
            CredentialValidationResult missing = await service.ValidateAsync("nobody", "whatever");
            Assert.False(missing.Success);
            Assert.Equal("invalid_credentials", missing.Error);

            // 用户存在但口令错误：错误码与"用户不存在"完全一致，外部不可区分（防用户名枚举）
            CredentialValidationResult wrongPassword = await service.ValidateAsync("alice", "wrong");
            Assert.False(wrongPassword.Success);
            Assert.Equal(missing.Error, wrongPassword.Error);

            // 正确口令仍可登录（假哈希逻辑不影响正常路径）
            CredentialValidationResult ok = await service.ValidateAsync("alice", "P@ssw0rd!");
            Assert.True(ok.Success);
        }

        // ---------------------------------------------------------------- JsonFileAuthStore 落盘异常安全

        [Fact]
        public async Task JsonFile存储_正常落盘_LastSaveError为null()
        {
            using var dir = new TempDir();
            string path = dir.File("auth-store.json");

            using var store = new JsonFileAuthStore(path, debounceMilliseconds: 1);
            await store.CreateAsync(new AuthUser { Id = "u1", UserName = "alice" });

            // 等待后台防抖定时器完成落盘（上限 5 秒，避免偶发调度延迟导致误报）
            for (int i = 0; i < 250 && !File.Exists(path); i++)
            {
                await Task.Delay(20);
            }

            Assert.True(File.Exists(path));
            Assert.Null(store.LastSaveError);
        }

        [Fact]
        public async Task JsonFile存储_后台落盘失败_不崩溃并记录LastSaveError()
        {
            using var dir = new TempDir();
            // 用一个普通文件挡住目录路径：Directory.CreateDirectory("<文件>/sub") 必然抛 IOException
            string blocker = dir.File("blocker");
            File.WriteAllText(blocker, "occupied");
            string path = Path.Combine(blocker, "sub", "auth-store.json");

            var store = new JsonFileAuthStore(path, debounceMilliseconds: 1);
            // 触发变更 → 防抖定时器 → 后台落盘失败。修复前该异常发生在 ThreadPool 线程上，
            // 未捕获会直接终止测试进程；修复后被吞掉并记入 LastSaveError。
            await store.CreateAsync(new AuthUser { Id = "u1", UserName = "alice" });

            for (int i = 0; i < 250 && store.LastSaveError == null; i++)
            {
                await Task.Delay(20);
            }

            Assert.NotNull(store.LastSaveError);
            // 存储本身仍可用（内存语义不受落盘失败影响）
            Assert.NotNull(await store.FindByIdAsync("u1"));

            // Dispose 会尝试补救性落盘，此场景下仍会失败，吞掉即可（不属于本修复的断言范围）
            try
            {
                store.Dispose();
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        // ---------------------------------------------------------------- 口令校验退化哈希拒绝

        [Fact]
        public void Pbkdf2Verify_空派生密钥段_任意口令都不通过()
        {
            var hasher = new Pbkdf2PasswordHasher();
            string salt = Convert.ToBase64String(new byte[16]);
            // 构造末段（派生密钥）为空的畸形哈希——修复前 FixedTimeEquals(空,空) 恒 true
            string degenerate = $"PBKDF2-SHA256$100000${salt}$";

            Assert.False(hasher.Verify(degenerate, "任意口令"));
            Assert.False(hasher.Verify(degenerate, ""));
            Assert.False(hasher.Verify(degenerate, "another-guess"));
        }

        [Fact]
        public void Pbkdf2Verify_空盐段_拒绝()
        {
            var hasher = new Pbkdf2PasswordHasher();
            string key = Convert.ToBase64String(new byte[32]);
            string degenerate = $"PBKDF2-SHA256$100000$${key}";
            Assert.False(hasher.Verify(degenerate, "x"));
        }

        [Fact]
        public void Pbkdf2Verify_正常哈希_往返仍成立()
        {
            var hasher = new Pbkdf2PasswordHasher();
            string hash = hasher.Hash("correct-horse");
            Assert.True(hasher.Verify(hash, "correct-horse"));
            Assert.False(hasher.Verify(hash, "wrong"));
        }

        // ---------------------------------------------------------------- 模型深拷贝隔离

        [Fact]
        public void AuthUserClone_深拷贝_修改副本不影响原对象()
        {
            var user = new AuthUser
            {
                UserName = "u",
                Roles = new List<string> { "r1" },
                DirectPermissions = new List<string> { "p1" },
                DeniedPermissions = new List<string> { "d1" },
                Claims = new Dictionary<string, string> { ["k"] = "v" },
            };
            AuthUser clone = user.Clone();
            clone.Roles.Add("r2");
            clone.DirectPermissions.Add("p2");
            clone.DeniedPermissions.Add("d2");
            clone.Claims["k2"] = "v2";
            clone.UserName = "changed";

            Assert.Single(user.Roles);
            Assert.Single(user.DirectPermissions);
            Assert.Single(user.DeniedPermissions);
            Assert.Single(user.Claims);
            Assert.Equal("u", user.UserName);
        }

        [Fact]
        public void AuthRoleClone_深拷贝_修改副本不影响原对象()
        {
            var role = new AuthRole
            {
                Name = "role",
                ParentRoles = new List<string> { "p" },
                Permissions = new List<string> { "a" },
                DeniedPermissions = new List<string> { "d" },
            };
            AuthRole clone = role.Clone();
            clone.ParentRoles.Add("p2");
            clone.Permissions.Add("a2");
            clone.DeniedPermissions.Add("d2");
            clone.Name = "changed";

            Assert.Single(role.ParentRoles);
            Assert.Single(role.Permissions);
            Assert.Single(role.DeniedPermissions);
            Assert.Equal("role", role.Name);
        }

        // ---------------------------------------------------------------- 按客户端吊销刷新令牌

        [Fact]
        public async Task RevokeClientRefreshTokens_使该客户端令牌失效()
        {
            var clock = new FakeClock();
            ServiceProvider sp = TestHost.Build(clock);
            var manager = sp.GetRequiredService<RefreshTokenManager>();
            var store = sp.GetRequiredService<InMemoryAuthStore>();

            (string tokenA, _) = await manager.IssueAsync("user1", "clientA", new[] { "s" });
            (string tokenB, _) = await manager.IssueAsync("user2", "clientB", new[] { "s" });

            await ((ITokenStore)store).RevokeClientRefreshTokensAsync("clientA");

            // clientA 的令牌被吊销，clientB 的不受影响
            var exchangeA = await manager.ExchangeAsync(tokenA, "clientA");
            Assert.False(exchangeA.Success);
            var exchangeB = await manager.ExchangeAsync(tokenB, "clientB");
            Assert.True(exchangeB.Success);
        }
    }
}
