using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;

namespace Cyaim.Authentication.Core.Stores
{
    /// <summary>
    /// 线程安全的内存授权存储：实现用户/角色/客户端/权限定义/令牌全部存储接口与版本号。
    /// 读写均深拷贝，外部修改返回对象不会污染存储。
    /// 适用于测试、示例与小型部署；持久化场景用 <see cref="JsonFileAuthStore"/> 或自行实现存储接口。
    /// </summary>
    public class InMemoryAuthStore : IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion
    {
        /// <summary>全局写锁</summary>
        protected readonly object Gate = new object();

        private readonly Dictionary<string, AuthUser> _usersById = new Dictionary<string, AuthUser>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _userIdByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, AuthRole> _rolesById = new Dictionary<string, AuthRole>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> _roleIdByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ClientApplication> _clients = new Dictionary<string, ClientApplication>(StringComparer.Ordinal);
        private readonly Dictionary<string, PermissionDefinition> _permissions = new Dictionary<string, PermissionDefinition>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, RefreshTokenRecord> _refreshTokens = new Dictionary<string, RefreshTokenRecord>(StringComparer.Ordinal);
        private readonly Dictionary<string, AuthorizationCodeRecord> _authCodes = new Dictionary<string, AuthorizationCodeRecord>(StringComparer.Ordinal);

        private long _version = 1;

        /// <inheritdoc/>
        public long Version => Interlocked.Read(ref _version);

        /// <inheritdoc/>
        public event Action<long>? Changed;

        /// <inheritdoc/>
        public void Bump()
        {
            long v = Interlocked.Increment(ref _version);
            Changed?.Invoke(v);
            OnMutated();
        }

        /// <summary>存储发生任何变更后回调（含不影响版本号的令牌写入），持久化子类重写</summary>
        protected virtual void OnMutated()
        {
        }

        private static T Clone<T>(T value) =>
            JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))!;

        // 权限评估热路径（每缓存未命中都读取用户/角色）改用手写深拷贝，避免 JSON 序列化往返开销
        private static AuthUser Clone(AuthUser value) => value.Clone();

        private static AuthRole Clone(AuthRole value) => value.Clone();

        #region IUserStore

        /// <inheritdoc/>
        public Task<AuthUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                return Task.FromResult(_usersById.TryGetValue(id, out AuthUser? user) ? Clone(user) : null);
            }
        }

        /// <inheritdoc/>
        public Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (userName != null && _userIdByName.TryGetValue(userName, out string? id) &&
                    _usersById.TryGetValue(id, out AuthUser? user))
                {
                    return Task.FromResult<AuthUser?>(Clone(user));
                }
                return Task.FromResult<AuthUser?>(null);
            }
        }

        /// <inheritdoc/>
        public Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (string.IsNullOrWhiteSpace(user.UserName))
                {
                    throw new ArgumentException("用户名不能为空", nameof(user));
                }
                if (_userIdByName.ContainsKey(user.UserName))
                {
                    throw new InvalidOperationException($"用户名已存在：{user.UserName}");
                }
                if (_usersById.ContainsKey(user.Id))
                {
                    throw new InvalidOperationException($"用户Id已存在：{user.Id}");
                }

                AuthUser stored = Clone(user);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _usersById[stored.Id] = stored;
                _userIdByName[stored.UserName] = stored.Id;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task UpdateAsync(AuthUser user, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (!_usersById.TryGetValue(user.Id, out AuthUser? existing))
                {
                    throw new InvalidOperationException($"用户不存在：{user.Id}");
                }
                if (!string.Equals(existing.UserName, user.UserName, StringComparison.OrdinalIgnoreCase))
                {
                    if (_userIdByName.ContainsKey(user.UserName))
                    {
                        throw new InvalidOperationException($"用户名已存在：{user.UserName}");
                    }
                    _userIdByName.Remove(existing.UserName);
                    _userIdByName[user.UserName] = user.Id;
                }

                AuthUser stored = Clone(user);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _usersById[user.Id] = stored;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task DeleteAsync(string id, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (_usersById.TryGetValue(id, out AuthUser? user))
                {
                    _usersById.Remove(id);
                    _userIdByName.Remove(user.UserName);
                }
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<IReadOnlyList<AuthUser>> ListAsync(string? search, int skip, int take, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                IReadOnlyList<AuthUser> result = FilterUsers(search)
                    .OrderBy(x => x.UserName, StringComparer.OrdinalIgnoreCase)
                    .Skip(skip).Take(take)
                    .Select(Clone)
                    .ToArray();
                return Task.FromResult(result);
            }
        }

        /// <inheritdoc/>
        public Task<int> CountAsync(string? search, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                return Task.FromResult(FilterUsers(search).Count());
            }
        }

        private IEnumerable<AuthUser> FilterUsers(string? search)
        {
            IEnumerable<AuthUser> users = _usersById.Values;
            if (!string.IsNullOrWhiteSpace(search))
            {
                users = users.Where(x =>
                    ContainsIgnoreCase(x.UserName, search!) ||
                    ContainsIgnoreCase(x.DisplayName, search!) ||
                    ContainsIgnoreCase(x.Email, search!));
            }
            return users;
        }

        private static bool ContainsIgnoreCase(string? text, string search) =>
            text != null && text.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;

        #endregion

        #region IRoleStore

        /// <inheritdoc/>
        Task<AuthRole?> IRoleStore.FindByIdAsync(string id, CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                return Task.FromResult(_rolesById.TryGetValue(id, out AuthRole? role) ? Clone(role) : null);
            }
        }

        /// <inheritdoc/>
        public Task<AuthRole?> FindByNameAsync(string name, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (name != null && _roleIdByName.TryGetValue(name, out string? id) &&
                    _rolesById.TryGetValue(id, out AuthRole? role))
                {
                    return Task.FromResult<AuthRole?>(Clone(role));
                }
                return Task.FromResult<AuthRole?>(null);
            }
        }

        /// <inheritdoc/>
        public Task<IReadOnlyList<AuthRole>> GetAllAsync(CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                IReadOnlyList<AuthRole> result = _rolesById.Values.Select(Clone).ToArray();
                return Task.FromResult(result);
            }
        }

        /// <inheritdoc/>
        public Task CreateAsync(AuthRole role, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (string.IsNullOrWhiteSpace(role.Name))
                {
                    throw new ArgumentException("角色名不能为空", nameof(role));
                }
                if (_roleIdByName.ContainsKey(role.Name))
                {
                    throw new InvalidOperationException($"角色名已存在：{role.Name}");
                }

                AuthRole stored = Clone(role);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _rolesById[stored.Id] = stored;
                _roleIdByName[stored.Name] = stored.Id;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task UpdateAsync(AuthRole role, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (!_rolesById.TryGetValue(role.Id, out AuthRole? existing))
                {
                    throw new InvalidOperationException($"角色不存在：{role.Id}");
                }
                if (!string.Equals(existing.Name, role.Name, StringComparison.OrdinalIgnoreCase))
                {
                    if (_roleIdByName.ContainsKey(role.Name))
                    {
                        throw new InvalidOperationException($"角色名已存在：{role.Name}");
                    }
                    _roleIdByName.Remove(existing.Name);
                    _roleIdByName[role.Name] = role.Id;
                }

                AuthRole stored = Clone(role);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _rolesById[role.Id] = stored;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        Task IRoleStore.DeleteAsync(string id, CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                if (_rolesById.TryGetValue(id, out AuthRole? role))
                {
                    if (role.IsSystem)
                    {
                        throw new InvalidOperationException($"系统内置角色不可删除：{role.Name}");
                    }
                    _rolesById.Remove(id);
                    _roleIdByName.Remove(role.Name);
                }
            }
            Bump();
            return Task.CompletedTask;
        }

        #endregion

        #region IClientStore

        /// <inheritdoc/>
        public Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                return Task.FromResult(clientId != null && _clients.TryGetValue(clientId, out ClientApplication? client)
                    ? Clone(client)
                    : null);
            }
        }

        /// <inheritdoc/>
        Task<IReadOnlyList<ClientApplication>> IClientStore.GetAllAsync(CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                IReadOnlyList<ClientApplication> result = _clients.Values
                    .OrderBy(x => x.ClientId, StringComparer.OrdinalIgnoreCase)
                    .Select(Clone).ToArray();
                return Task.FromResult(result);
            }
        }

        /// <inheritdoc/>
        public Task CreateAsync(ClientApplication client, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (string.IsNullOrWhiteSpace(client.ClientId))
                {
                    throw new ArgumentException("客户端Id不能为空", nameof(client));
                }
                if (_clients.ContainsKey(client.ClientId))
                {
                    throw new InvalidOperationException($"客户端已存在：{client.ClientId}");
                }

                ClientApplication stored = Clone(client);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _clients[stored.ClientId] = stored;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task UpdateAsync(ClientApplication client, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                if (!_clients.ContainsKey(client.ClientId))
                {
                    throw new InvalidOperationException($"客户端不存在：{client.ClientId}");
                }

                ClientApplication stored = Clone(client);
                stored.UpdatedAt = DateTimeOffset.UtcNow;
                _clients[client.ClientId] = stored;
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        Task IClientStore.DeleteAsync(string clientId, CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                _clients.Remove(clientId);
            }
            Bump();
            return Task.CompletedTask;
        }

        #endregion

        #region IPermissionDefinitionStore

        /// <inheritdoc/>
        public Task UpsertAsync(IEnumerable<PermissionDefinition> definitions, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                foreach (PermissionDefinition def in definitions)
                {
                    if (string.IsNullOrWhiteSpace(def.Code))
                    {
                        continue;
                    }
                    _permissions[def.Code] = Clone(def);
                }
            }
            Bump();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        Task<IReadOnlyList<PermissionDefinition>> IPermissionDefinitionStore.GetAllAsync(CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                IReadOnlyList<PermissionDefinition> result = _permissions.Values
                    .OrderBy(x => x.Code, StringComparer.OrdinalIgnoreCase)
                    .Select(Clone).ToArray();
                return Task.FromResult(result);
            }
        }

        /// <inheritdoc/>
        Task IPermissionDefinitionStore.DeleteAsync(string code, CancellationToken cancellationToken)
        {
            lock (Gate)
            {
                _permissions.Remove(code);
            }
            Bump();
            return Task.CompletedTask;
        }

        #endregion

        #region ITokenStore

        /// <inheritdoc/>
        public Task SaveRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                _refreshTokens[record.TokenHash] = Clone(record);
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<RefreshTokenRecord?> FindRefreshTokenAsync(string tokenHash, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                return Task.FromResult(_refreshTokens.TryGetValue(tokenHash, out RefreshTokenRecord? record)
                    ? Clone(record)
                    : null);
            }
        }

        /// <inheritdoc/>
        public Task UpdateRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                _refreshTokens[record.TokenHash] = Clone(record);
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            RefreshTokenConsumeResult result;
            bool mutated = false;
            lock (Gate)
            {
                if (!_refreshTokens.TryGetValue(tokenHash, out RefreshTokenRecord? record))
                {
                    result = new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound, null);
                }
                else if (record.RevokedAt != null)
                {
                    result = new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked, Clone(record));
                }
                else if (record.ConsumedAt != null)
                {
                    result = new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.AlreadyConsumed, Clone(record));
                }
                else if (record.ExpiresAt <= now)
                {
                    result = new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired, Clone(record));
                }
                else
                {
                    // 原子转换：活跃 → 已消费。锁内完成 check-then-set，并发下只有一次成功。
                    record.ConsumedAt = now;
                    mutated = true;
                    result = new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Consumed, Clone(record));
                }
            }
            if (mutated)
            {
                OnMutated();
            }
            return Task.FromResult(result);
        }

        /// <inheritdoc/>
        public Task RevokeRefreshTokenFamilyAsync(string familyId, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            lock (Gate)
            {
                foreach (RefreshTokenRecord record in _refreshTokens.Values)
                {
                    if (record.FamilyId == familyId && record.RevokedAt == null)
                    {
                        record.RevokedAt = now;
                    }
                }
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task RevokeSubjectRefreshTokensAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            lock (Gate)
            {
                foreach (RefreshTokenRecord record in _refreshTokens.Values)
                {
                    if (record.SubjectId == subjectId &&
                        (clientId == null || record.ClientId == clientId) &&
                        record.RevokedAt == null)
                    {
                        record.RevokedAt = now;
                    }
                }
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task RevokeClientRefreshTokensAsync(string clientId, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            lock (Gate)
            {
                foreach (RefreshTokenRecord record in _refreshTokens.Values)
                {
                    if (record.ClientId == clientId && record.RevokedAt == null)
                    {
                        record.RevokedAt = now;
                    }
                }
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task SaveAuthorizationCodeAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken = default)
        {
            lock (Gate)
            {
                _authCodes[record.CodeHash] = Clone(record);
            }
            OnMutated();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<AuthorizationCodeRecord?> ConsumeAuthorizationCodeAsync(string codeHash, CancellationToken cancellationToken = default)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            AuthorizationCodeRecord? result = null;
            lock (Gate)
            {
                if (_authCodes.TryGetValue(codeHash, out AuthorizationCodeRecord? record) &&
                    record.ConsumedAt == null &&
                    record.ExpiresAt > now)
                {
                    record.ConsumedAt = now;
                    result = Clone(record);
                }
            }
            OnMutated();
            return Task.FromResult(result);
        }

        /// <inheritdoc/>
        public Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
        {
            int removed = 0;
            lock (Gate)
            {
                foreach (string key in _refreshTokens.Where(x => x.Value.ExpiresAt <= now).Select(x => x.Key).ToArray())
                {
                    _refreshTokens.Remove(key);
                    removed++;
                }
                foreach (string key in _authCodes.Where(x => x.Value.ExpiresAt <= now).Select(x => x.Key).ToArray())
                {
                    _authCodes.Remove(key);
                    removed++;
                }
            }
            if (removed > 0)
            {
                OnMutated();
            }
            return Task.FromResult(removed);
        }

        #endregion

        #region 快照（持久化子类使用）

        /// <summary>存储快照（序列化用）</summary>
        protected internal sealed class Snapshot
        {
            /// <summary>数据版本</summary>
            public long Version { get; set; }
            /// <summary>用户</summary>
            public List<AuthUser> Users { get; set; } = new List<AuthUser>();
            /// <summary>角色</summary>
            public List<AuthRole> Roles { get; set; } = new List<AuthRole>();
            /// <summary>客户端</summary>
            public List<ClientApplication> Clients { get; set; } = new List<ClientApplication>();
            /// <summary>权限定义</summary>
            public List<PermissionDefinition> Permissions { get; set; } = new List<PermissionDefinition>();
            /// <summary>刷新令牌</summary>
            public List<RefreshTokenRecord> RefreshTokens { get; set; } = new List<RefreshTokenRecord>();
            /// <summary>授权码</summary>
            public List<AuthorizationCodeRecord> AuthorizationCodes { get; set; } = new List<AuthorizationCodeRecord>();
        }

        /// <summary>导出当前快照</summary>
        protected internal Snapshot ExportSnapshot()
        {
            lock (Gate)
            {
                return new Snapshot
                {
                    Version = Version,
                    Users = _usersById.Values.Select(Clone).ToList(),
                    Roles = _rolesById.Values.Select(Clone).ToList(),
                    Clients = _clients.Values.Select(Clone).ToList(),
                    Permissions = _permissions.Values.Select(Clone).ToList(),
                    RefreshTokens = _refreshTokens.Values.Select(Clone).ToList(),
                    AuthorizationCodes = _authCodes.Values.Select(Clone).ToList(),
                };
            }
        }

        /// <summary>从快照恢复（替换全部数据，不触发持久化回调）</summary>
        protected internal void ImportSnapshot(Snapshot snapshot)
        {
            lock (Gate)
            {
                _usersById.Clear();
                _userIdByName.Clear();
                _rolesById.Clear();
                _roleIdByName.Clear();
                _clients.Clear();
                _permissions.Clear();
                _refreshTokens.Clear();
                _authCodes.Clear();

                foreach (AuthUser user in snapshot.Users)
                {
                    _usersById[user.Id] = user;
                    _userIdByName[user.UserName] = user.Id;
                }
                foreach (AuthRole role in snapshot.Roles)
                {
                    _rolesById[role.Id] = role;
                    _roleIdByName[role.Name] = role.Id;
                }
                foreach (ClientApplication client in snapshot.Clients)
                {
                    _clients[client.ClientId] = client;
                }
                foreach (PermissionDefinition def in snapshot.Permissions)
                {
                    _permissions[def.Code] = def;
                }
                foreach (RefreshTokenRecord token in snapshot.RefreshTokens)
                {
                    _refreshTokens[token.TokenHash] = token;
                }
                foreach (AuthorizationCodeRecord code in snapshot.AuthorizationCodes)
                {
                    _authCodes[code.CodeHash] = code;
                }

                Interlocked.Exchange(ref _version, Math.Max(1, snapshot.Version));
            }
        }

        #endregion
    }
}
