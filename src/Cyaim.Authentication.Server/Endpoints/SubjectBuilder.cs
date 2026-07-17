using System;
using System.Collections.Generic;
using System.Linq;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 从存储模型构建令牌签发主体。
    /// </summary>
    internal static class SubjectBuilder
    {
        /// <summary>
        /// 从用户账户构建用户主体（Claims 含 preferred_username 与 sstamp 安全戳）。
        /// </summary>
        public static AuthSubject FromUser(AuthUser user, string? clientId, IReadOnlyList<string> scopes, string? sessionId)
        {
            var claims = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in user.Claims)
            {
                claims[pair.Key] = pair.Value;
            }
            claims[AuthConstants.ClaimTypes.PreferredUserName] = user.UserName;
            claims[AuthConstants.ClaimTypes.SecurityStamp] = user.SecurityStamp;
            if (!string.IsNullOrEmpty(user.Email))
            {
                claims[AuthConstants.ClaimTypes.Email] = user.Email!;
            }

            return new AuthSubject
            {
                Id = user.Id,
                Name = user.DisplayName ?? user.UserName,
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.User,
                Roles = user.Roles.ToArray(),
                DirectPermissions = user.DirectPermissions.ToArray(),
                DeniedPermissions = user.DeniedPermissions.ToArray(),
                Scopes = scopes,
                ClientId = clientId,
                SessionId = sessionId,
                Claims = claims,
            };
        }

        /// <summary>
        /// 从客户端应用构建客户端主体（client_credentials 模式）。
        /// </summary>
        public static AuthSubject FromClient(ClientApplication client, IReadOnlyList<string> scopes)
        {
            return new AuthSubject
            {
                Id = client.ClientId,
                Name = client.ClientName ?? client.ClientId,
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.Client,
                DirectPermissions = client.Permissions.ToArray(),
                Scopes = scopes,
                ClientId = client.ClientId,
            };
        }
    }
}
