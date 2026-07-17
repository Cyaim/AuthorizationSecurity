using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.EntityFrameworkCore;

namespace Cyaim.Authentication.EntityFrameworkCore
{
    /// <summary>
    /// 基于 EF Core 的授权数据存储：实现五个数据存储接口（用户/角色/客户端/权限定义/令牌）。
    /// <para>
    /// 以单例注册，通过 <see cref="IDbContextFactory{TContext}"/> 每次操作创建短生命周期上下文，
    /// 因此可安全供单例的权限评估器使用（避免捕获 Scoped 的 DbContext）。
    /// </para>
    /// <para>
    /// 令牌的一次性消费用 <c>ExecuteUpdate</c> 的条件更新实现数据库级原子性——多实例并发下
    /// 同一刷新令牌/授权码只会被消费一次，据此在集群中正确进行轮换重放检测与授权码防重放。
    /// </para>
    /// <para>影响授权结果的写操作（用户/角色/客户端/权限定义）在提交后调用 <see cref="IAuthStoreVersion.Bump"/>，
    /// 由集群版本广播使全集群权限集缓存失效。</para>
    /// </summary>
    public class EntityFrameworkAuthStore
        : IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore
    {
        private readonly IDbContextFactory<CyaimAuthDbContext> _factory;
        private readonly IAuthStoreVersion _version;

        /// <summary>创建存储。</summary>
        public EntityFrameworkAuthStore(IDbContextFactory<CyaimAuthDbContext> factory, IAuthStoreVersion version)
        {
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));
            _version = version ?? throw new ArgumentNullException(nameof(version));
        }

        #region IUserStore

        /// <inheritdoc/>
        public async Task<AuthUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            // 用户名唯一但大小写不敏感——EF 端拉候选后在内存精确匹配（不依赖数据库排序规则）
            List<AuthUser> candidates = await db.Users.AsNoTracking()
                .Where(x => x.UserName == userName).ToListAsync(cancellationToken).ConfigureAwait(false);
            return candidates.FirstOrDefault(x => string.Equals(x.UserName, userName, StringComparison.OrdinalIgnoreCase))
                   ?? await FindByUserNameSlowAsync(db, userName, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<AuthUser?> FindByUserNameSlowAsync(CyaimAuthDbContext db, string userName, CancellationToken ct)
        {
            // 回退：全表大小写不敏感匹配（仅当精确匹配未命中时，兼顾不同排序规则）
            foreach (AuthUser u in await db.Users.AsNoTracking().ToListAsync(ct).ConfigureAwait(false))
            {
                if (string.Equals(u.UserName, userName, StringComparison.OrdinalIgnoreCase))
                {
                    return u;
                }
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default)
        {
            // 用户名大小写不敏感唯一（数据库 PK/唯一索引为大小写敏感的原子兜底；此处按契约做不敏感预检）
            if (await FindByUserNameAsync(user.UserName, cancellationToken).ConfigureAwait(false) != null)
            {
                throw new InvalidOperationException($"用户名已存在：{user.UserName}");
            }
            await CreateEntityAsync(user, bumpVersion: true, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task UpdateAsync(AuthUser user, CancellationToken cancellationToken = default)
        {
            AuthUser? existing = await FindByIdAsync(user.Id, cancellationToken).ConfigureAwait(false);
            if (existing == null)
            {
                throw new InvalidOperationException($"用户不存在：{user.Id}");
            }
            if (!string.Equals(existing.UserName, user.UserName, StringComparison.OrdinalIgnoreCase))
            {
                AuthUser? other = await FindByUserNameAsync(user.UserName, cancellationToken).ConfigureAwait(false);
                if (other != null && other.Id != user.Id)
                {
                    throw new InvalidOperationException($"用户名已存在：{user.UserName}");
                }
            }
            user.UpdatedAt = DateTimeOffset.UtcNow;
            await UpdateEntityAsync(user, bumpVersion: true, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public Task DeleteAsync(string id, CancellationToken cancellationToken = default) =>
            DeleteUserAsync(id, cancellationToken);

        private async Task DeleteUserAsync(string id, CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            int affected = await db.Users.Where(x => x.Id == id).ExecuteDeleteAsync(ct).ConfigureAwait(false);
            if (affected > 0)
            {
                _version.Bump();
            }
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<AuthUser>> ListAsync(string? search, int skip, int take, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await FilterUsers(db, search)
                .OrderBy(x => x.UserName)
                .Skip(skip).Take(take)
                .AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<int> CountAsync(string? search, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await FilterUsers(db, search).CountAsync(cancellationToken).ConfigureAwait(false);
        }

        private static IQueryable<AuthUser> FilterUsers(CyaimAuthDbContext db, string? search)
        {
            IQueryable<AuthUser> q = db.Users;
            if (!string.IsNullOrWhiteSpace(search))
            {
                string s = search!;
                q = q.Where(x => x.UserName.Contains(s)
                              || (x.DisplayName != null && x.DisplayName.Contains(s))
                              || (x.Email != null && x.Email.Contains(s)));
            }
            return q;
        }

        #endregion

        #region IRoleStore

        Task<AuthRole?> IRoleStore.FindByIdAsync(string id, CancellationToken cancellationToken) => FindRoleByIdAsync(id, cancellationToken);

        private async Task<AuthRole?> FindRoleByIdAsync(string id, CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            return await db.Roles.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<AuthRole?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            foreach (AuthRole r in await db.Roles.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false))
            {
                if (string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    return r;
                }
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task<IReadOnlyList<AuthRole>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await db.Roles.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task CreateAsync(AuthRole role, CancellationToken cancellationToken = default)
        {
            if (await FindByNameAsync(role.Name, cancellationToken).ConfigureAwait(false) != null)
            {
                throw new InvalidOperationException($"角色名已存在：{role.Name}");
            }
            await CreateEntityAsync(role, bumpVersion: true, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task UpdateAsync(AuthRole role, CancellationToken cancellationToken = default)
        {
            AuthRole? existing = await FindRoleByIdAsync(role.Id, cancellationToken).ConfigureAwait(false);
            if (existing == null)
            {
                throw new InvalidOperationException($"角色不存在：{role.Id}");
            }
            if (!string.Equals(existing.Name, role.Name, StringComparison.OrdinalIgnoreCase))
            {
                AuthRole? other = await FindByNameAsync(role.Name, cancellationToken).ConfigureAwait(false);
                if (other != null && other.Id != role.Id)
                {
                    throw new InvalidOperationException($"角色名已存在：{role.Name}");
                }
            }
            role.UpdatedAt = DateTimeOffset.UtcNow;
            await UpdateEntityAsync(role, bumpVersion: true, cancellationToken).ConfigureAwait(false);
        }

        Task IRoleStore.DeleteAsync(string id, CancellationToken cancellationToken) => DeleteRoleAsync(id, cancellationToken);

        private async Task DeleteRoleAsync(string id, CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            AuthRole? role = await db.Roles.FirstOrDefaultAsync(x => x.Id == id, ct).ConfigureAwait(false);
            if (role == null)
            {
                return;
            }
            if (role.IsSystem)
            {
                throw new InvalidOperationException($"系统内置角色不可删除：{role.Name}");
            }
            db.Roles.Remove(role);
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            _version.Bump();
        }

        #endregion

        #region IClientStore

        /// <inheritdoc/>
        public async Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await db.Clients.AsNoTracking().FirstOrDefaultAsync(x => x.ClientId == clientId, cancellationToken).ConfigureAwait(false);
        }

        Task<IReadOnlyList<ClientApplication>> IClientStore.GetAllAsync(CancellationToken cancellationToken) => GetAllClientsAsync(cancellationToken);

        private async Task<IReadOnlyList<ClientApplication>> GetAllClientsAsync(CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            return await db.Clients.AsNoTracking().OrderBy(x => x.ClientId).ToListAsync(ct).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public Task CreateAsync(ClientApplication client, CancellationToken cancellationToken = default) =>
            CreateEntityAsync(client, bumpVersion: true, cancellationToken);

        /// <inheritdoc/>
        public Task UpdateAsync(ClientApplication client, CancellationToken cancellationToken = default)
        {
            client.UpdatedAt = DateTimeOffset.UtcNow;
            return UpdateEntityAsync(client, bumpVersion: true, cancellationToken);
        }

        Task IClientStore.DeleteAsync(string clientId, CancellationToken cancellationToken) => DeleteClientAsync(clientId, cancellationToken);

        private async Task DeleteClientAsync(string clientId, CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            int affected = await db.Clients.Where(x => x.ClientId == clientId).ExecuteDeleteAsync(ct).ConfigureAwait(false);
            if (affected > 0)
            {
                _version.Bump();
            }
        }

        #endregion

        #region IPermissionDefinitionStore

        /// <inheritdoc/>
        public async Task UpsertAsync(IEnumerable<PermissionDefinition> definitions, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            bool any = false;
            foreach (PermissionDefinition def in definitions)
            {
                if (string.IsNullOrWhiteSpace(def.Code))
                {
                    continue;
                }
                PermissionDefinition? existing = await db.PermissionDefinitions.FirstOrDefaultAsync(x => x.Code == def.Code, cancellationToken).ConfigureAwait(false);
                if (existing == null)
                {
                    db.PermissionDefinitions.Add(def);
                }
                else
                {
                    existing.DisplayName = def.DisplayName;
                    existing.Description = def.Description;
                    existing.Group = def.Group;
                    existing.Origin = def.Origin;
                }
                any = true;
            }
            if (any)
            {
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                _version.Bump();
            }
        }

        Task<IReadOnlyList<PermissionDefinition>> IPermissionDefinitionStore.GetAllAsync(CancellationToken cancellationToken) => GetAllPermissionDefsAsync(cancellationToken);

        private async Task<IReadOnlyList<PermissionDefinition>> GetAllPermissionDefsAsync(CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            return await db.PermissionDefinitions.AsNoTracking().OrderBy(x => x.Code).ToListAsync(ct).ConfigureAwait(false);
        }

        Task IPermissionDefinitionStore.DeleteAsync(string code, CancellationToken cancellationToken) => DeletePermissionDefAsync(code, cancellationToken);

        private async Task DeletePermissionDefAsync(string code, CancellationToken ct)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            int affected = await db.PermissionDefinitions.Where(x => x.Code == code).ExecuteDeleteAsync(ct).ConfigureAwait(false);
            if (affected > 0)
            {
                _version.Bump();
            }
        }

        #endregion

        #region ITokenStore

        /// <inheritdoc/>
        public async Task SaveRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            db.RefreshTokens.Add(record);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<RefreshTokenRecord?> FindRefreshTokenAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            return await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task UpdateRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            db.RefreshTokens.Update(record);
            try
            {
                await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DbUpdateConcurrencyException)
            {
                // 记录已不存在，忽略
            }
        }

        /// <inheritdoc/>
        public async Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            // 先按主键读取（时间比较在内存判断，避免部分提供程序如 SQLite 无法在批量更新中翻译 DateTimeOffset 比较）
            RefreshTokenRecord? record = await db.RefreshTokens.AsNoTracking()
                .FirstOrDefaultAsync(x => x.TokenHash == tokenHash, cancellationToken).ConfigureAwait(false);
            if (record == null)
            {
                return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound, null);
            }
            if (record.RevokedAt != null)
            {
                return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked, record);
            }
            if (record.ConsumedAt != null)
            {
                return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.AlreadyConsumed, record);
            }
            if (record.ExpiresAt <= now)
            {
                return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired, record);
            }

            // 原子消费：仅当仍未消费/未吊销时置为已消费（null 守卫保证并发下只有一次 affected==1，杜绝重放绕过）
            int affected = await db.RefreshTokens
                .Where(x => x.TokenHash == tokenHash && x.ConsumedAt == null && x.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), cancellationToken)
                .ConfigureAwait(false);

            return affected == 1
                ? new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Consumed, record)
                : new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.AlreadyConsumed, record); // 并发被他人抢先
        }

        /// <inheritdoc/>
        public async Task RevokeRefreshTokenFamilyAsync(string familyId, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            await db.RefreshTokens.Where(x => x.FamilyId == familyId && x.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task RevokeSubjectRefreshTokensAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            await db.RefreshTokens
                .Where(x => x.SubjectId == subjectId && x.RevokedAt == null && (clientId == null || x.ClientId == clientId))
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task RevokeClientRefreshTokensAsync(string clientId, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            await db.RefreshTokens.Where(x => x.ClientId == clientId && x.RevokedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task SaveAuthorizationCodeAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
            db.AuthorizationCodes.Add(record);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public async Task<AuthorizationCodeRecord?> ConsumeAuthorizationCodeAsync(string codeHash, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            AuthorizationCodeRecord? record = await db.AuthorizationCodes.AsNoTracking()
                .FirstOrDefaultAsync(x => x.CodeHash == codeHash, cancellationToken).ConfigureAwait(false);
            if (record == null || record.ConsumedAt != null || record.ExpiresAt <= now)
            {
                return null;
            }

            // 原子一次性消费：null 守卫保证并发下只有一次成功
            int affected = await db.AuthorizationCodes
                .Where(x => x.CodeHash == codeHash && x.ConsumedAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), cancellationToken)
                .ConfigureAwait(false);

            return affected == 1 ? record : null;
        }

        /// <inheritdoc/>
        public async Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);

            // 先选出过期记录主键（时间比较在物化后于内存判断，保证各提供程序可移植），再按主键批量删除
            List<RefreshTokenRecord> rt = await db.RefreshTokens.AsNoTracking()
                .Select(x => new RefreshTokenRecord { TokenHash = x.TokenHash, ExpiresAt = x.ExpiresAt })
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            var expiredRt = rt.Where(x => x.ExpiresAt <= now).Select(x => x.TokenHash).ToList();

            List<AuthorizationCodeRecord> ac = await db.AuthorizationCodes.AsNoTracking()
                .Select(x => new AuthorizationCodeRecord { CodeHash = x.CodeHash, ExpiresAt = x.ExpiresAt })
                .ToListAsync(cancellationToken).ConfigureAwait(false);
            var expiredAc = ac.Where(x => x.ExpiresAt <= now).Select(x => x.CodeHash).ToList();

            int a = expiredRt.Count == 0 ? 0
                : await db.RefreshTokens.Where(x => expiredRt.Contains(x.TokenHash)).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            int b = expiredAc.Count == 0 ? 0
                : await db.AuthorizationCodes.Where(x => expiredAc.Contains(x.CodeHash)).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            return a + b;
        }

        #endregion

        #region 通用写入

        private async Task CreateEntityAsync<TEntity>(TEntity entity, bool bumpVersion, CancellationToken ct) where TEntity : class
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            db.Add(entity);
            try
            {
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                throw new InvalidOperationException("创建失败：唯一性冲突（主键或名称已存在）", ex);
            }
            if (bumpVersion)
            {
                _version.Bump();
            }
        }

        private async Task UpdateEntityAsync<TEntity>(TEntity entity, bool bumpVersion, CancellationToken ct) where TEntity : class
        {
            await using CyaimAuthDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
            db.Update(entity);
            try
            {
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                throw new InvalidOperationException("更新失败：目标记录不存在", ex);
            }
            catch (DbUpdateException ex)
            {
                throw new InvalidOperationException("更新失败：唯一性冲突（名称已被占用）", ex);
            }
            if (bumpVersion)
            {
                _version.Bump();
            }
        }

        #endregion
    }
}
