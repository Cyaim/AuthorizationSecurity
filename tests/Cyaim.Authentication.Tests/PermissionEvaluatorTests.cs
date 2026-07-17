using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="IPermissionEvaluator"/> 集成测试：真实 DI 容器 + 内存存储 + 可控时钟。
    /// </summary>
    public class PermissionEvaluatorTests
    {
        private static AuthSubject UserSubject(string id) => new AuthSubject
        {
            Id = id,
            IsAuthenticated = true,
            SubjectType = AuthSubjectType.User,
        };

        private static async Task<string> CreateUserAsync(
            InMemoryAuthStore store, string id, string userName,
            IEnumerable<string>? permissions = null, IEnumerable<string>? roles = null)
        {
            var user = new AuthUser { Id = id, UserName = userName };
            if (permissions != null)
            {
                user.DirectPermissions.AddRange(permissions);
            }
            if (roles != null)
            {
                user.Roles.AddRange(roles);
            }
            await store.CreateAsync(user);
            return id;
        }

        private static Task CreateRoleAsync(
            InMemoryAuthStore store, string name,
            IEnumerable<string>? permissions = null,
            IEnumerable<string>? deniedPermissions = null,
            IEnumerable<string>? parents = null)
        {
            var role = new AuthRole { Name = name };
            if (permissions != null)
            {
                role.Permissions.AddRange(permissions);
            }
            if (deniedPermissions != null)
            {
                role.DeniedPermissions.AddRange(deniedPermissions);
            }
            if (parents != null)
            {
                role.ParentRoles.AddRange(parents);
            }
            return store.CreateAsync(role);
        }

        [Fact]
        public async Task 用户直接权限_命中()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateUserAsync(store, "u1", "alice", permissions: new[] { "doc.read" });

            Assert.True(await evaluator.IsGrantedAsync(UserSubject("u1"), "doc.read"));
            Assert.False(await evaluator.IsGrantedAsync(UserSubject("u1"), "doc.write"));
        }

        [Fact]
        public async Task 角色权限_命中()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "editor", permissions: new[] { "doc.edit" });
            await CreateUserAsync(store, "u1", "alice", roles: new[] { "editor" });

            Assert.True(await evaluator.IsGrantedAsync(UserSubject("u1"), "doc.edit"));
        }

        [Fact]
        public async Task 角色层级_继承父角色权限()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "base", permissions: new[] { "sys.read" });
            await CreateRoleAsync(store, "child", permissions: new[] { "sys.write" }, parents: new[] { "base" });
            await CreateUserAsync(store, "u1", "alice", roles: new[] { "child" });

            Assert.True(await evaluator.IsGrantedAsync(UserSubject("u1"), "sys.read"));
            Assert.True(await evaluator.IsGrantedAsync(UserSubject("u1"), "sys.write"));
        }

        [Fact]
        public async Task 角色层级_菱形继承正常展开()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "top", permissions: new[] { "diamond.top" });
            await CreateRoleAsync(store, "left", permissions: new[] { "diamond.left" }, parents: new[] { "top" });
            await CreateRoleAsync(store, "right", permissions: new[] { "diamond.right" }, parents: new[] { "top" });
            await CreateRoleAsync(store, "bottom", parents: new[] { "left", "right" });
            await CreateUserAsync(store, "u1", "alice", roles: new[] { "bottom" });

            AuthSubject subject = UserSubject("u1");
            Assert.True(await evaluator.IsGrantedAsync(subject, "diamond.top"));
            Assert.True(await evaluator.IsGrantedAsync(subject, "diamond.left"));
            Assert.True(await evaluator.IsGrantedAsync(subject, "diamond.right"));
        }

        [Fact]
        public async Task 角色层级_循环不死循环()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "r1", permissions: new[] { "cyc.a" }, parents: new[] { "r2" });
            await CreateRoleAsync(store, "r2", permissions: new[] { "cyc.b" }, parents: new[] { "r1" });
            await CreateUserAsync(store, "u1", "alice", roles: new[] { "r1" });

            Task<bool> check = evaluator.IsGrantedAsync(UserSubject("u1"), "cyc.b");
            Task completed = await Task.WhenAny(check, Task.Delay(TimeSpan.FromSeconds(5)));

            Assert.Same(check, completed);
            Assert.True(await check);
        }

        [Fact]
        public async Task 角色拒绝_覆盖用户直接允许()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "restricted", deniedPermissions: new[] { "doc.read" });
            await CreateUserAsync(store, "u1", "alice",
                permissions: new[] { "doc.read" }, roles: new[] { "restricted" });

            AuthorizationDecision decision = await evaluator.EvaluateAsync(UserSubject("u1"), "doc.read");

            Assert.False(decision.IsGranted);
            Assert.Equal(AuthorizationReason.DeniedByRule, decision.Reason);
        }

        [Fact]
        public async Task 禁用用户_SubjectDisabled()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            var user = new AuthUser { Id = "u1", UserName = "alice", IsEnabled = false };
            user.DirectPermissions.Add("doc.read");
            await store.CreateAsync(user);

            AuthorizationDecision decision = await evaluator.EvaluateAsync(UserSubject("u1"), "doc.read");

            Assert.False(decision.IsGranted);
            Assert.Equal(AuthorizationReason.SubjectDisabled, decision.Reason);
        }

        [Fact]
        public async Task 锁定用户_SubjectDisabled_解锁后恢复()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            var user = new AuthUser
            {
                Id = "u1",
                UserName = "alice",
                LockoutEnd = clock.UtcNow + TimeSpan.FromHours(1),
            };
            user.DirectPermissions.Add("doc.read");
            await store.CreateAsync(user);

            AuthorizationDecision locked = await evaluator.EvaluateAsync(UserSubject("u1"), "doc.read");
            Assert.Equal(AuthorizationReason.SubjectDisabled, locked.Reason);

            // 过锁定期（同时超过缓存TTL确保重建）
            clock.Advance(TimeSpan.FromHours(2));
            AuthorizationDecision unlocked = await evaluator.EvaluateAsync(UserSubject("u1"), "doc.read");
            Assert.True(unlocked.IsGranted);
        }

        [Fact]
        public async Task 游客_按GuestRoles评估()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock, o => o.GuestRoles.Add("guest"));
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "guest", permissions: new[] { "public.read" });

            AuthSubject guest = AuthSubject.Guest();
            Assert.True(await evaluator.IsGrantedAsync(guest, "public.read"));

            AuthorizationDecision denied = await evaluator.EvaluateAsync(guest, "private.read");
            Assert.False(denied.IsGranted);
            Assert.Equal(AuthorizationReason.GuestNotAllowed, denied.Reason);
        }

        [Fact]
        public async Task 存储无此用户_回退令牌声明()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            var subject = new AuthSubject
            {
                Id = "remote-user",
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.User,
                DirectPermissions = new[] { "api.call" },
                DeniedPermissions = new[] { "api.admin" },
            };

            Assert.True(await evaluator.IsGrantedAsync(subject, "api.call"));
            AuthorizationDecision denied = await evaluator.EvaluateAsync(subject, "api.admin");
            Assert.Equal(AuthorizationReason.DeniedByRule, denied.Reason);
        }

        [Fact]
        public async Task 客户端主体_使用客户端存储的权限()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            var client = new ClientApplication { ClientId = "cli1" };
            client.Permissions.Add("api.invoke");
            await store.CreateAsync(client);

            var subject = new AuthSubject
            {
                Id = "cli1",
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.Client,
                ClientId = "cli1",
            };

            Assert.True(await evaluator.IsGrantedAsync(subject, "api.invoke"));
            Assert.False(await evaluator.IsGrantedAsync(subject, "api.other"));
        }

        [Fact]
        public async Task 缓存_第二次TryGetCachedPermissionSet命中()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateUserAsync(store, "u1", "alice", permissions: new[] { "doc.read" });
            AuthSubject subject = UserSubject("u1");

            Assert.False(evaluator.TryGetCachedPermissionSet(subject, out _));

            await evaluator.GetPermissionSetAsync(subject);

            Assert.True(evaluator.TryGetCachedPermissionSet(subject, out CompiledPermissionSet cached));
            Assert.True(cached.IsGranted("doc.read"));
        }

        [Fact]
        public async Task 缓存_版本变化后失效_角色权限变更立刻生效()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateRoleAsync(store, "editor", permissions: new[] { "doc.edit" });
            await CreateUserAsync(store, "u1", "alice", roles: new[] { "editor" });
            AuthSubject subject = UserSubject("u1");

            Assert.False(await evaluator.IsGrantedAsync(subject, "doc.publish"));

            // 更新角色权限（UpdateAsync 内部 Bump 版本号）
            AuthRole role = (await store.FindByNameAsync("editor"))!;
            role.Permissions.Add("doc.publish");
            await ((Cyaim.Authentication.Abstractions.Stores.IRoleStore)store).UpdateAsync(role);

            Assert.True(await evaluator.IsGrantedAsync(subject, "doc.publish"));
        }

        [Fact]
        public async Task 缓存_TTL过期后重建()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock, o => o.PermissionCacheTtl = TimeSpan.FromMinutes(1));
            var store = sp.GetRequiredService<InMemoryAuthStore>();
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            await CreateUserAsync(store, "u1", "alice", permissions: new[] { "doc.read" });
            AuthSubject subject = UserSubject("u1");

            await evaluator.GetPermissionSetAsync(subject);
            Assert.True(evaluator.TryGetCachedPermissionSet(subject, out _));

            clock.Advance(TimeSpan.FromMinutes(2));
            Assert.False(evaluator.TryGetCachedPermissionSet(subject, out _));

            // 重建后依然可用且重新缓存
            Assert.True(await evaluator.IsGrantedAsync(subject, "doc.read"));
            Assert.True(evaluator.TryGetCachedPermissionSet(subject, out _));
        }

        [Fact]
        public async Task 策略_命中返回结果()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock, builder: b => b
                .AddPolicy("always-yes", _ => true)
                .AddPolicy("always-no", _ => false));
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();
            AuthSubject subject = UserSubject("u1");

            AuthorizationDecision yes = await evaluator.EvaluatePolicyAsync(subject, "always-yes");
            Assert.True(yes.IsGranted);
            Assert.Equal(AuthorizationReason.GrantedByPolicy, yes.Reason);
            Assert.Equal("always-yes", yes.PolicyName);

            AuthorizationDecision no = await evaluator.EvaluatePolicyAsync(subject, "always-no");
            Assert.False(no.IsGranted);
            Assert.Equal(AuthorizationReason.PolicyNotSatisfied, no.Reason);
        }

        [Fact]
        public async Task 策略_不存在返回PolicyNotFound()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock);
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();

            AuthorizationDecision decision = await evaluator.EvaluatePolicyAsync(UserSubject("u1"), "missing");

            Assert.False(decision.IsGranted);
            Assert.Equal(AuthorizationReason.PolicyNotFound, decision.Reason);
        }

        [Fact]
        public async Task 策略_抛异常按拒绝处理()
        {
            var clock = new FakeClock();
            using ServiceProvider sp = TestHost.Build(clock, builder: b => b
                .AddPolicy("boom", _ => throw new InvalidOperationException("boom")));
            var evaluator = sp.GetRequiredService<IPermissionEvaluator>();

            AuthorizationDecision decision = await evaluator.EvaluatePolicyAsync(UserSubject("u1"), "boom");

            Assert.False(decision.IsGranted);
            Assert.Equal(AuthorizationReason.PolicyNotSatisfied, decision.Reason);
        }
    }
}
