using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Services
{
    /// <summary>
    /// 令牌服务：签发与校验 JWT 访问令牌，导出 JWKS 公钥集。
    /// </summary>
    public interface ITokenService
    {
        /// <summary>令牌签发者（iss）</summary>
        string Issuer { get; }

        /// <summary>
        /// 签发访问令牌。
        /// </summary>
        Task<IssuedToken> IssueAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// 校验访问令牌（签名、有效期、签发者、受众）。
        /// </summary>
        Task<AccessTokenValidation> ValidateAccessTokenAsync(string accessToken, CancellationToken cancellationToken = default);

        /// <summary>
        /// 获取 JWKS 公钥集 JSON（对称密钥时返回空 keys 数组）。
        /// </summary>
        string GetJwksJson();
    }

    /// <summary>
    /// 访问令牌签发请求。
    /// </summary>
    public class AccessTokenRequest
    {
        /// <summary>令牌主体</summary>
        public AuthSubject Subject { get; set; } = AuthSubject.Guest();

        /// <summary>签发目标客户端（可空，写入 client_id 声明）</summary>
        public ClientApplication? Client { get; set; }

        /// <summary>授予的作用域</summary>
        public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();

        /// <summary>有效期；空则用客户端或全局默认值</summary>
        public TimeSpan? Lifetime { get; set; }

        /// <summary>是否把主体的有效权限写入 perm 声明（离线判断用；权限多时令牌会变大）</summary>
        public bool IncludePermissionClaims { get; set; }

        /// <summary>写入 perm 声明的权限代码（由调用方计算）</summary>
        public IReadOnlyList<string>? PermissionCodes { get; set; }

        /// <summary>附加声明</summary>
        public IDictionary<string, string>? ExtraClaims { get; set; }
    }

    /// <summary>
    /// 已签发令牌。
    /// </summary>
    public class IssuedToken
    {
        /// <summary>令牌文本</summary>
        public string Token { get; set; } = string.Empty;

        /// <summary>令牌Id（jti）</summary>
        public string TokenId { get; set; } = string.Empty;

        /// <summary>过期时间</summary>
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>有效期秒数</summary>
        public int ExpiresInSeconds { get; set; }
    }

    /// <summary>
    /// 访问令牌校验结果。
    /// </summary>
    public class AccessTokenValidation
    {
        /// <summary>是否有效</summary>
        public bool IsValid { get; set; }

        /// <summary>无效原因</summary>
        public string? Error { get; set; }

        /// <summary>解析出的主体</summary>
        public AuthSubject? Subject { get; set; }

        /// <summary>声明主体（与 ASP.NET Core 集成）</summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>过期时间</summary>
        public DateTimeOffset? ExpiresAt { get; set; }

        /// <summary>令牌Id（jti）</summary>
        public string? TokenId { get; set; }

        /// <summary>创建失败结果</summary>
        public static AccessTokenValidation Fail(string error) => new AccessTokenValidation { IsValid = false, Error = error };
    }
}
