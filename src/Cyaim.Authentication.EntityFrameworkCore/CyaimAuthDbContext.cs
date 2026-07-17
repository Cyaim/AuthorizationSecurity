using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Cyaim.Authentication.Abstractions.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Cyaim.Authentication.EntityFrameworkCore
{
    /// <summary>
    /// Cyaim.Authentication 的 EF Core 数据上下文：把授权域模型映射到关系表，
    /// 列表/字典属性以 JSON 列存储。可用于任意 EF Core 关系型提供程序
    /// （PostgreSQL / SQL Server / SQLite 等），从而支撑多实例共享数据库的集群部署。
    /// </summary>
    public class CyaimAuthDbContext : DbContext
    {
        /// <summary>创建上下文。</summary>
        public CyaimAuthDbContext(DbContextOptions<CyaimAuthDbContext> options) : base(options)
        {
        }

        /// <summary>用户表</summary>
        public DbSet<AuthUser> Users => Set<AuthUser>();

        /// <summary>角色表</summary>
        public DbSet<AuthRole> Roles => Set<AuthRole>();

        /// <summary>客户端表</summary>
        public DbSet<ClientApplication> Clients => Set<ClientApplication>();

        /// <summary>权限定义表</summary>
        public DbSet<PermissionDefinition> PermissionDefinitions => Set<PermissionDefinition>();

        /// <summary>刷新令牌表</summary>
        public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();

        /// <summary>授权码表</summary>
        public DbSet<AuthorizationCodeRecord> AuthorizationCodes => Set<AuthorizationCodeRecord>();

        /// <summary>集群版本单行表</summary>
        public DbSet<ClusterVersionRow> ClusterVersion => Set<ClusterVersionRow>();

        /// <inheritdoc/>
        protected override void OnModelCreating(ModelBuilder b)
        {
            ValueConverter<List<string>, string> listConv = JsonConverter<List<string>>();
            ValueComparer<List<string>> listCmp = ListComparer();
            ValueConverter<Dictionary<string, string>, string> dictConv = JsonConverter<Dictionary<string, string>>();
            ValueComparer<Dictionary<string, string>> dictCmp = DictComparer();

            b.Entity<AuthUser>(e =>
            {
                e.ToTable("CyaimAuthUsers");
                e.HasKey(x => x.Id);
                e.Property(x => x.Id).HasMaxLength(64);
                e.Property(x => x.UserName).HasMaxLength(256).IsRequired();
                e.HasIndex(x => x.UserName).IsUnique();
                e.Property(x => x.Roles).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.DirectPermissions).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.DeniedPermissions).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.Claims).HasConversion(dictConv).Metadata.SetValueComparer(dictCmp);
                e.Ignore("Item"); // 无索引器，防御性
            });

            b.Entity<AuthRole>(e =>
            {
                e.ToTable("CyaimAuthRoles");
                e.HasKey(x => x.Id);
                e.Property(x => x.Id).HasMaxLength(64);
                e.Property(x => x.Name).HasMaxLength(256).IsRequired();
                e.HasIndex(x => x.Name).IsUnique();
                e.Property(x => x.ParentRoles).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.Permissions).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.DeniedPermissions).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
            });

            b.Entity<ClientApplication>(e =>
            {
                e.ToTable("CyaimAuthClients");
                e.HasKey(x => x.ClientId);
                e.Property(x => x.ClientId).HasMaxLength(256);
                e.Property(x => x.AllowedGrantTypes).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.RedirectUris).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.PostLogoutRedirectUris).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.AllowedScopes).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.Permissions).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
                e.Property(x => x.AllowedCorsOrigins).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
            });

            b.Entity<PermissionDefinition>(e =>
            {
                e.ToTable("CyaimAuthPermissionDefinitions");
                e.HasKey(x => x.Code);
                e.Property(x => x.Code).HasMaxLength(512);
            });

            b.Entity<RefreshTokenRecord>(e =>
            {
                e.ToTable("CyaimAuthRefreshTokens");
                e.HasKey(x => x.TokenHash);
                e.Property(x => x.TokenHash).HasMaxLength(128);
                e.HasIndex(x => x.FamilyId);
                e.HasIndex(x => x.SubjectId);
                e.HasIndex(x => x.ClientId);
                e.HasIndex(x => x.ExpiresAt);
                e.Property(x => x.Scopes).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
            });

            b.Entity<AuthorizationCodeRecord>(e =>
            {
                e.ToTable("CyaimAuthAuthorizationCodes");
                e.HasKey(x => x.CodeHash);
                e.Property(x => x.CodeHash).HasMaxLength(128);
                e.HasIndex(x => x.ExpiresAt);
                e.Property(x => x.Scopes).HasConversion(listConv).Metadata.SetValueComparer(listCmp);
            });

            b.Entity<ClusterVersionRow>(e =>
            {
                e.ToTable("CyaimAuthClusterVersion");
                e.HasKey(x => x.Id);
            });
        }

        private static ValueConverter<T, string> JsonConverter<T>() => new ValueConverter<T, string>(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            s => string.IsNullOrEmpty(s) ? default! : JsonSerializer.Deserialize<T>(s, (JsonSerializerOptions?)null)!);

        private static ValueComparer<List<string>> ListComparer() => new ValueComparer<List<string>>(
            (a, c) => (a ?? new List<string>()).SequenceEqual(c ?? new List<string>()),
            v => v == null ? 0 : v.Aggregate(0, (h, s) => HashCode.Combine(h, s.GetHashCode())),
            v => v == null ? new List<string>() : new List<string>(v));

        private static ValueComparer<Dictionary<string, string>> DictComparer() => new ValueComparer<Dictionary<string, string>>(
            (a, c) => DictEquals(a, c),
            v => v == null ? 0 : v.Aggregate(0, (h, kv) => HashCode.Combine(h, kv.Key.GetHashCode(), kv.Value.GetHashCode())),
            v => v == null ? new Dictionary<string, string>() : new Dictionary<string, string>(v));

        private static bool DictEquals(Dictionary<string, string>? a, Dictionary<string, string>? c)
        {
            a ??= new Dictionary<string, string>();
            c ??= new Dictionary<string, string>();
            if (a.Count != c.Count)
            {
                return false;
            }
            foreach (KeyValuePair<string, string> kv in a)
            {
                if (!c.TryGetValue(kv.Key, out string? v) || v != kv.Value)
                {
                    return false;
                }
            }
            return true;
        }
    }

    /// <summary>
    /// 集群版本单行实体（<c>Id</c> 恒为 1，<c>Version</c> 全集群单调递增）。
    /// </summary>
    public class ClusterVersionRow
    {
        /// <summary>固定主键（恒为 1）</summary>
        public int Id { get; set; } = 1;

        /// <summary>当前集群版本</summary>
        public long Version { get; set; }
    }
}
