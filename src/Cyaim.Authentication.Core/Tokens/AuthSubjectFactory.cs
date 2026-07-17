using System;
using System.Collections.Generic;
using System.Security.Claims;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Core.Tokens
{
    /// <summary>
    /// 从声明构建 <see cref="AuthSubject"/>。
    /// </summary>
    public static class AuthSubjectFactory
    {
        /// <summary>
        /// 从声明身份构建主体（声明名遵循 <see cref="AuthConstants.ClaimTypes"/>）。
        /// </summary>
        public static AuthSubject FromClaimsIdentity(ClaimsIdentity identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            string? sub = null;
            string? name = null;
            string? clientId = null;
            string? sessionId = null;
            var roles = new List<string>();
            var perms = new List<string>();
            var scopes = new List<string>();
            var extraClaims = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (Claim claim in identity.Claims)
            {
                switch (claim.Type)
                {
                    case AuthConstants.ClaimTypes.Subject:
                        sub = claim.Value;
                        break;
                    case ClaimTypes.NameIdentifier:
                        sub ??= claim.Value;
                        break;
                    case AuthConstants.ClaimTypes.Name:
                        name = claim.Value;
                        extraClaims[claim.Type] = claim.Value;
                        break;
                    case AuthConstants.ClaimTypes.ClientId:
                        clientId = claim.Value;
                        extraClaims[claim.Type] = claim.Value;
                        break;
                    case AuthConstants.ClaimTypes.SessionId:
                        sessionId = claim.Value;
                        extraClaims[claim.Type] = claim.Value;
                        break;
                    case AuthConstants.ClaimTypes.Role:
                    case ClaimTypes.Role:
                        roles.Add(claim.Value);
                        break;
                    case AuthConstants.ClaimTypes.Permission:
                        perms.Add(claim.Value);
                        break;
                    case AuthConstants.ClaimTypes.Scope:
                        scopes.AddRange(claim.Value.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries));
                        break;
                    case AuthConstants.ClaimTypes.Issuer:
                    case AuthConstants.ClaimTypes.Audience:
                    case "exp":
                    case "nbf":
                    case "iat":
                        break;
                    default:
                        if (!extraClaims.ContainsKey(claim.Type))
                        {
                            extraClaims[claim.Type] = claim.Value;
                        }
                        break;
                }
            }

            bool isClient = clientId != null && clientId == sub;
            return new AuthSubject
            {
                Id = sub ?? string.Empty,
                Name = name,
                IsAuthenticated = !string.IsNullOrEmpty(sub),
                SubjectType = isClient ? AuthSubjectType.Client : AuthSubjectType.User,
                Roles = roles.ToArray(),
                DirectPermissions = perms.ToArray(),
                Scopes = scopes.ToArray(),
                ClientId = clientId,
                SessionId = sessionId,
                Claims = extraClaims,
            };
        }
    }
}
