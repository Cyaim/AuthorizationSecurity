using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;

namespace Cyaim.Authentication.Core
{
    /// <summary>
    /// 初始数据播种器：幂等创建用户、角色、客户端与权限定义（示例与首次部署用）。
    /// </summary>
    public sealed class AuthDataSeeder
    {
        private readonly IUserStore _users;
        private readonly IRoleStore _roles;
        private readonly IClientStore _clients;
        private readonly IPermissionDefinitionStore _permissions;
        private readonly IPasswordHasher _hasher;

        /// <summary>创建播种器</summary>
        public AuthDataSeeder(
            IUserStore users, IRoleStore roles, IClientStore clients,
            IPermissionDefinitionStore permissions, IPasswordHasher hasher)
        {
            _users = users;
            _roles = roles;
            _clients = clients;
            _permissions = permissions;
            _hasher = hasher;
        }

        /// <summary>
        /// 确保角色存在（存在则不修改）。
        /// </summary>
        public async Task<AuthRole> EnsureRoleAsync(
            string name, IEnumerable<string>? permissions = null,
            IEnumerable<string>? parentRoles = null, IEnumerable<string>? deniedPermissions = null,
            string? displayName = null, bool isSystem = false, CancellationToken cancellationToken = default)
        {
            AuthRole? existing = await _roles.FindByNameAsync(name, cancellationToken).ConfigureAwait(false);
            if (existing != null)
            {
                return existing;
            }

            var role = new AuthRole
            {
                Name = name,
                DisplayName = displayName ?? name,
                Permissions = permissions?.ToList() ?? new List<string>(),
                ParentRoles = parentRoles?.ToList() ?? new List<string>(),
                DeniedPermissions = deniedPermissions?.ToList() ?? new List<string>(),
                IsSystem = isSystem,
            };
            await _roles.CreateAsync(role, cancellationToken).ConfigureAwait(false);
            return role;
        }

        /// <summary>
        /// 确保用户存在（存在则不修改）。
        /// </summary>
        public async Task<AuthUser> EnsureUserAsync(
            string userName, string password, IEnumerable<string>? roles = null,
            IEnumerable<string>? directPermissions = null, string? displayName = null,
            string? email = null, CancellationToken cancellationToken = default)
        {
            AuthUser? existing = await _users.FindByUserNameAsync(userName, cancellationToken).ConfigureAwait(false);
            if (existing != null)
            {
                return existing;
            }

            var user = new AuthUser
            {
                UserName = userName,
                DisplayName = displayName ?? userName,
                Email = email,
                PasswordHash = _hasher.Hash(password),
                Roles = roles?.ToList() ?? new List<string>(),
                DirectPermissions = directPermissions?.ToList() ?? new List<string>(),
            };
            await _users.CreateAsync(user, cancellationToken).ConfigureAwait(false);
            return user;
        }

        /// <summary>
        /// 确保客户端存在（存在则原样返回不修改），返回该客户端。
        /// </summary>
        public async Task<ClientApplication> EnsureClientAsync(
            string clientId, string? clientSecret, IEnumerable<string> allowedGrantTypes,
            IEnumerable<string>? allowedScopes = null, IEnumerable<string>? redirectUris = null,
            IEnumerable<string>? permissions = null, bool allowOfflineAccess = false,
            string? clientName = null, bool requirePkce = true,
            IEnumerable<string>? postLogoutRedirectUris = null,
            CancellationToken cancellationToken = default)
        {
            ClientApplication? existing = await _clients.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false);
            if (existing != null)
            {
                return existing;
            }

            var client = new ClientApplication
            {
                ClientId = clientId,
                ClientName = clientName ?? clientId,
                ClientSecretHash = string.IsNullOrEmpty(clientSecret) ? null : _hasher.Hash(clientSecret!),
                AllowedGrantTypes = allowedGrantTypes.ToList(),
                AllowedScopes = allowedScopes?.ToList() ?? new List<string>(),
                RedirectUris = redirectUris?.ToList() ?? new List<string>(),
                PostLogoutRedirectUris = postLogoutRedirectUris?.ToList() ?? new List<string>(),
                Permissions = permissions?.ToList() ?? new List<string>(),
                AllowOfflineAccess = allowOfflineAccess,
                RequirePkce = requirePkce,
            };
            await _clients.CreateAsync(client, cancellationToken).ConfigureAwait(false);
            return client;
        }

        /// <summary>
        /// 登记权限定义。
        /// </summary>
        public Task EnsurePermissionDefinitionsAsync(
            IEnumerable<(string Code, string? DisplayName, string? Group)> definitions,
            CancellationToken cancellationToken = default)
        {
            return _permissions.UpsertAsync(
                definitions.Select(d => new PermissionDefinition
                {
                    Code = d.Code,
                    DisplayName = d.DisplayName ?? d.Code,
                    Group = d.Group,
                    Origin = PermissionOrigin.Manual,
                }),
                cancellationToken);
        }
    }
}
