using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Tokens;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="JwtTokenService"/> 测试：HS256 / RS256 签发校验、JWKS。
    /// </summary>
    public class JwtTokenServiceTests
    {
        private const string HmacKey = "0123456789abcdef0123456789abcdef"; // 32 字节

        private static CyaimAuthCoreOptions HmacOptions(Action<CyaimAuthCoreOptions>? configure = null)
        {
            var options = new CyaimAuthCoreOptions { HmacSigningKey = HmacKey };
            configure?.Invoke(options);
            return options;
        }

        private static JwtTokenService CreateService(CyaimAuthCoreOptions options, IAuthClock clock) =>
            new JwtTokenService(Options.Create(options), clock, NullLogger<JwtTokenService>.Instance);

        [Fact]
        public async Task HS256_签发校验往返_声明完整还原()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(), clock);
            var subject = new AuthSubject
            {
                Id = "u1",
                Name = "Alice Zhang",
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.User,
                Roles = new[] { "admin", "editor" },
                ClientId = "web-app",
                SessionId = "sess-1",
                Claims = new Dictionary<string, string>
                {
                    [AuthConstants.ClaimTypes.SecurityStamp] = "stamp-1",
                },
            };

            IssuedToken issued = await service.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = subject,
                Scopes = new[] { "openid", "profile" },
                IncludePermissionClaims = true,
                PermissionCodes = new[] { "doc.read", "doc.write" },
                ExtraClaims = new Dictionary<string, string> { ["tenant"] = "acme" },
            });

            Assert.False(string.IsNullOrEmpty(issued.Token));
            Assert.False(string.IsNullOrEmpty(issued.TokenId));

            AccessTokenValidation validation = await service.ValidateAccessTokenAsync(issued.Token);

            Assert.True(validation.IsValid);
            AuthSubject restored = validation.Subject!;
            Assert.Equal("u1", restored.Id);
            Assert.Equal("Alice Zhang", restored.Name);
            Assert.True(restored.IsAuthenticated);
            Assert.Equal(AuthSubjectType.User, restored.SubjectType);
            Assert.Equal(new[] { "admin", "editor" }, restored.Roles.OrderBy(x => x));
            Assert.Equal(new[] { "doc.read", "doc.write" }, restored.DirectPermissions.OrderBy(x => x));
            // scope 以空格拼接后再还原为列表
            Assert.Equal(new[] { "openid", "profile" }, restored.Scopes);
            Assert.Equal("web-app", restored.ClientId);
            Assert.Equal("sess-1", restored.SessionId);
            Assert.Equal("stamp-1", restored.Claims[AuthConstants.ClaimTypes.SecurityStamp]);
            Assert.Equal("acme", restored.Claims["tenant"]);
            Assert.Equal(issued.TokenId, validation.TokenId);
            Assert.NotNull(validation.Principal);
            Assert.NotNull(validation.ExpiresAt);
        }

        [Fact]
        public async Task HS256_过期令牌拒绝()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(o => o.ClockSkew = TimeSpan.FromSeconds(30)), clock);
            IssuedToken issued = await service.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = new AuthSubject { Id = "u1", IsAuthenticated = true },
                Lifetime = TimeSpan.FromMinutes(5),
            });

            // 未过期时有效
            Assert.True((await service.ValidateAccessTokenAsync(issued.Token)).IsValid);

            // 推进超过有效期 + ClockSkew
            clock.Advance(TimeSpan.FromMinutes(6));
            AccessTokenValidation validation = await service.ValidateAccessTokenAsync(issued.Token);

            Assert.False(validation.IsValid);
            Assert.NotNull(validation.Error);
        }

        [Fact]
        public async Task HS256_错误签名密钥拒绝()
        {
            var clock = new FakeClock();
            JwtTokenService issuer = CreateService(HmacOptions(), clock);
            JwtTokenService other = CreateService(
                HmacOptions(o => o.HmacSigningKey = "another-secret-key-32-bytes-long!!"), clock);

            IssuedToken issued = await issuer.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = new AuthSubject { Id = "u1", IsAuthenticated = true },
            });

            Assert.False((await other.ValidateAccessTokenAsync(issued.Token)).IsValid);
        }

        [Fact]
        public async Task HS256_错误issuer或audience拒绝()
        {
            var clock = new FakeClock();
            JwtTokenService issuer = CreateService(HmacOptions(), clock);
            JwtTokenService wrongIssuer = CreateService(HmacOptions(o => o.Issuer = "other-issuer"), clock);
            JwtTokenService wrongAudience = CreateService(HmacOptions(o => o.Audience = "other-api"), clock);

            IssuedToken issued = await issuer.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = new AuthSubject { Id = "u1", IsAuthenticated = true },
            });

            Assert.False((await wrongIssuer.ValidateAccessTokenAsync(issued.Token)).IsValid);
            Assert.False((await wrongAudience.ValidateAccessTokenAsync(issued.Token)).IsValid);
        }

        [Fact]
        public async Task 空令牌拒绝()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(), clock);

            AccessTokenValidation validation = await service.ValidateAccessTokenAsync("");

            Assert.False(validation.IsValid);
            Assert.Equal("empty_token", validation.Error);
        }

        [Fact]
        public void HS256_短密钥构造抛异常()
        {
            var clock = new FakeClock();
            var options = new CyaimAuthCoreOptions { HmacSigningKey = "too-short" };

            Assert.Throws<InvalidOperationException>(() => CreateService(options, clock));
        }

        [Fact]
        public async Task RS256_密钥文件自动生成且二次启动复用()
        {
            using var dir = new TempDir();
            string keyPath = dir.File("signing-key.json");
            var clock = new FakeClock();
            var options = new CyaimAuthCoreOptions { RsaKeyFilePath = keyPath };

            JwtTokenService first = CreateService(options, clock);
            Assert.True(File.Exists(keyPath));

            IssuedToken issued = await first.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = new AuthSubject { Id = "u1", IsAuthenticated = true },
            });
            Assert.True((await first.ValidateAccessTokenAsync(issued.Token)).IsValid);

            // 二次启动：复用同一密钥（kid 一致，可校验先前签发的令牌）
            JwtTokenService second = CreateService(options, clock);
            Assert.True((await second.ValidateAccessTokenAsync(issued.Token)).IsValid);
            Assert.Equal(GetKid(first.GetJwksJson()), GetKid(second.GetJwksJson()));
        }

        [Fact]
        public void JWKS_RS256包含公钥参数()
        {
            using var dir = new TempDir();
            var clock = new FakeClock();
            JwtTokenService service = CreateService(
                new CyaimAuthCoreOptions { RsaKeyFilePath = dir.File("key.json") }, clock);

            using JsonDocument doc = JsonDocument.Parse(service.GetJwksJson());
            JsonElement key = doc.RootElement.GetProperty("keys")[0];

            Assert.Equal("RSA", key.GetProperty("kty").GetString());
            Assert.Equal("RS256", key.GetProperty("alg").GetString());
            Assert.False(string.IsNullOrEmpty(key.GetProperty("kid").GetString()));
            Assert.False(string.IsNullOrEmpty(key.GetProperty("n").GetString()));
            Assert.False(string.IsNullOrEmpty(key.GetProperty("e").GetString()));
        }

        [Fact]
        public void JWKS_HS256返回空keys数组()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(), clock);

            using JsonDocument doc = JsonDocument.Parse(service.GetJwksJson());

            Assert.Equal(0, doc.RootElement.GetProperty("keys").GetArrayLength());
        }

        [Fact]
        public async Task 客户端凭据主体_sub等于client_id_还原为Client类型()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(), clock);
            var client = new ClientApplication { ClientId = "cli1" };
            var subject = new AuthSubject
            {
                Id = "cli1",
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.Client,
            };

            IssuedToken issued = await service.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = subject,
                Client = client,
            });
            AccessTokenValidation validation = await service.ValidateAccessTokenAsync(issued.Token);

            Assert.True(validation.IsValid);
            Assert.Equal(AuthSubjectType.Client, validation.Subject!.SubjectType);
            Assert.Equal("cli1", validation.Subject.Id);
            Assert.Equal("cli1", validation.Subject.ClientId);
        }

        [Fact]
        public async Task 有效期_使用客户端配置()
        {
            var clock = new FakeClock();
            JwtTokenService service = CreateService(HmacOptions(), clock);
            var client = new ClientApplication { ClientId = "cli1", AccessTokenLifetimeSeconds = 120 };

            IssuedToken issued = await service.IssueAccessTokenAsync(new AccessTokenRequest
            {
                Subject = new AuthSubject { Id = "u1", IsAuthenticated = true },
                Client = client,
            });

            Assert.Equal(120, issued.ExpiresInSeconds);
            Assert.Equal(clock.UtcNow + TimeSpan.FromSeconds(120), issued.ExpiresAt);
        }

        private static string? GetKid(string jwksJson)
        {
            using JsonDocument doc = JsonDocument.Parse(jwksJson);
            return doc.RootElement.GetProperty("keys")[0].GetProperty("kid").GetString();
        }
    }
}
