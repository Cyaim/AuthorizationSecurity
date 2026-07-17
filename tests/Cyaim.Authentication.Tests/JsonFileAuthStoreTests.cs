using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Core.Stores;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="JsonFileAuthStore"/> 测试：落盘与重新加载。
    /// </summary>
    public class JsonFileAuthStoreTests
    {
        [Fact]
        public async Task 写入后新实例加载数据一致()
        {
            using var dir = new TempDir();
            string path = dir.File("auth-store.json");

            long version;
            using (var first = new JsonFileAuthStore(path))
            {
                var user = new AuthUser { Id = "u1", UserName = "alice" };
                user.DirectPermissions.Add("doc.read");
                await first.CreateAsync(user);

                var role = new AuthRole { Id = "r1", Name = "editor" };
                role.Permissions.Add("doc.edit");
                await first.CreateAsync(role);

                await first.CreateAsync(new ClientApplication { ClientId = "cli1", ClientName = "App" });

                await first.SaveRefreshTokenAsync(new RefreshTokenRecord
                {
                    TokenHash = "hash1",
                    SubjectId = "u1",
                    ClientId = "cli1",
                    ExpiresAt = DateTimeOffset.UtcNow.AddDays(7),
                });

                version = first.Version;
                first.SaveNow();
            }

            using var second = new JsonFileAuthStore(path);

            AuthUser? user2 = await second.FindByIdAsync("u1");
            Assert.NotNull(user2);
            Assert.Equal("alice", user2!.UserName);
            Assert.Equal(new[] { "doc.read" }, user2.DirectPermissions);

            AuthRole? role2 = await second.FindByNameAsync("editor");
            Assert.NotNull(role2);
            Assert.Equal(new[] { "doc.edit" }, role2!.Permissions);

            ClientApplication? client2 = await second.FindByClientIdAsync("cli1");
            Assert.NotNull(client2);
            Assert.Equal("App", client2!.ClientName);

            RefreshTokenRecord? token2 = await second.FindRefreshTokenAsync("hash1");
            Assert.NotNull(token2);
            Assert.Equal("u1", token2!.SubjectId);

            Assert.Equal(version, second.Version);
        }

        [Fact]
        public async Task SaveNow_文件存在且JSON可解析()
        {
            using var dir = new TempDir();
            string path = dir.File("auth-store.json");

            using var store = new JsonFileAuthStore(path);
            await store.CreateAsync(new AuthUser { Id = "u1", UserName = "alice" });
            store.SaveNow();

            Assert.True(File.Exists(path));

            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
            Assert.Equal(1, doc.RootElement.GetProperty("Users").GetArrayLength());
            Assert.True(doc.RootElement.GetProperty("Version").GetInt64() >= 1);
        }

        [Fact]
        public void 文件不存在时_创建空存储()
        {
            using var dir = new TempDir();
            using var store = new JsonFileAuthStore(dir.File("missing.json"));

            Assert.Equal(1, store.Version);
        }
    }
}
