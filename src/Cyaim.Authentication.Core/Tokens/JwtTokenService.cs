using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core.Engine;
using Cyaim.Authentication.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cyaim.Authentication.Core.Tokens
{
    /// <summary>
    /// JWT 访问令牌服务（RFC 7519 / RFC 9068 风格声明）。
    /// 配置 <see cref="CyaimAuthCoreOptions.HmacSigningKey"/> 使用 HS256；
    /// 否则使用 RSA（RS256），密钥自动生成并持久化到 <see cref="CyaimAuthCoreOptions.RsaKeyFilePath"/>。
    /// </summary>
    public sealed class JwtTokenService : ITokenService
    {
        private readonly CyaimAuthCoreOptions _options;
        private readonly IAuthClock _clock;
        private readonly ILogger<JwtTokenService> _logger;
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        private readonly SecurityKey _signingKey;
        private readonly string _algorithm;
        private readonly string? _keyId;
        private readonly RSAParameters? _rsaPublicParameters;
        private readonly TokenValidationParameters _validationParameters;
        private readonly string _jwksJson;

        /// <inheritdoc/>
        public string Issuer => _options.Issuer;

        /// <summary>
        /// 创建令牌服务并初始化签名密钥。
        /// </summary>
        public JwtTokenService(
            IOptions<CyaimAuthCoreOptions> options,
            IAuthClock clock,
            ILogger<JwtTokenService> logger)
        {
            _options = options.Value;
            _clock = clock;
            _logger = logger;

            if (!string.IsNullOrEmpty(_options.HmacSigningKey))
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(_options.HmacSigningKey);
                if (keyBytes.Length < 32)
                {
                    throw new InvalidOperationException("HMAC 签名密钥长度不足：HS256 要求至少 32 字节");
                }
                _signingKey = new SymmetricSecurityKey(keyBytes);
                _algorithm = SecurityAlgorithms.HmacSha256;
                _keyId = null;
                _rsaPublicParameters = null;
            }
            else
            {
                RSAParameters parameters = LoadOrCreateRsaKey();
                var rsa = RSA.Create();
                rsa.ImportParameters(parameters);
                _keyId = ComputeKeyId(parameters);
                _signingKey = new RsaSecurityKey(rsa) { KeyId = _keyId };
                _algorithm = SecurityAlgorithms.RsaSha256;
                _rsaPublicParameters = new RSAParameters { Modulus = parameters.Modulus, Exponent = parameters.Exponent };
            }

            // 校验参数与 JWKS 在密钥固定后不变，构建一次复用（避免每次校验/每次 JWKS 请求重复分配）
            _validationParameters = BuildValidationParameters();
            _jwksJson = BuildJwksJson();
        }

        private TokenValidationParameters BuildValidationParameters()
        {
            return new TokenValidationParameters
            {
                ValidIssuer = _options.Issuer,
                ValidAudience = _options.Audience,
                IssuerSigningKey = _signingKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ValidAlgorithms = new[] { _algorithm },
                ClockSkew = _options.ClockSkew,
                // 用框架时钟校验有效期（可测试）
                LifetimeValidator = (notBefore, expires, token, p) =>
                {
                    DateTime now = _clock.UtcNow.UtcDateTime;
                    if (notBefore.HasValue && notBefore.Value > now + p.ClockSkew)
                    {
                        return false;
                    }
                    return expires.HasValue && expires.Value >= now - p.ClockSkew;
                },
            };
        }

        /// <inheritdoc/>
        public Task<IssuedToken> IssueAccessTokenAsync(AccessTokenRequest request, CancellationToken cancellationToken = default)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            AuthSubject subject = request.Subject;
            DateTimeOffset now = _clock.UtcNow;
            TimeSpan lifetime = request.Lifetime
                ?? (request.Client != null ? TimeSpan.FromSeconds(request.Client.AccessTokenLifetimeSeconds) : _options.DefaultAccessTokenLifetime);
            DateTimeOffset expiresAt = now + lifetime;
            string tokenId = Guid.NewGuid().ToString("N");

            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [AuthConstants.ClaimTypes.Subject] = subject.Id,
                [AuthConstants.ClaimTypes.TokenId] = tokenId,
            };

            if (!string.IsNullOrEmpty(subject.Name))
            {
                claims[AuthConstants.ClaimTypes.Name] = subject.Name!;
            }
            if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.PreferredUserName, out string? userName))
            {
                claims[AuthConstants.ClaimTypes.PreferredUserName] = userName;
            }
            if (!string.IsNullOrEmpty(request.Client?.ClientId))
            {
                claims[AuthConstants.ClaimTypes.ClientId] = request.Client!.ClientId;
            }
            else if (!string.IsNullOrEmpty(subject.ClientId))
            {
                claims[AuthConstants.ClaimTypes.ClientId] = subject.ClientId!;
            }
            if (!string.IsNullOrEmpty(subject.SessionId))
            {
                claims[AuthConstants.ClaimTypes.SessionId] = subject.SessionId!;
            }
            if (subject.Claims.TryGetValue(AuthConstants.ClaimTypes.SecurityStamp, out string? stamp))
            {
                claims[AuthConstants.ClaimTypes.SecurityStamp] = stamp;
            }
            if (subject.Roles.Count > 0)
            {
                claims[AuthConstants.ClaimTypes.Role] = subject.Roles.ToArray();
            }
            if (request.Scopes.Count > 0)
            {
                // RFC 9068 §2.2.3：scope 为空格分隔字符串
                claims[AuthConstants.ClaimTypes.Scope] = string.Join(" ", request.Scopes);
            }
            if (request.IncludePermissionClaims && request.PermissionCodes != null && request.PermissionCodes.Count > 0)
            {
                claims[AuthConstants.ClaimTypes.Permission] = request.PermissionCodes.ToArray();
            }
            if (request.ExtraClaims != null)
            {
                foreach (KeyValuePair<string, string> extra in request.ExtraClaims)
                {
                    if (!claims.ContainsKey(extra.Key))
                    {
                        claims[extra.Key] = extra.Value;
                    }
                }
            }

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = _options.Issuer,
                Audience = _options.Audience,
                IssuedAt = now.UtcDateTime,
                NotBefore = now.UtcDateTime,
                Expires = expiresAt.UtcDateTime,
                Claims = claims,
                SigningCredentials = new SigningCredentials(_signingKey, _algorithm),
            };

            string token = _handler.CreateToken(descriptor);

            AuthMetrics.RecordTokenIssued(subject.SubjectType == AuthSubjectType.Client ? "client" : "user");
            _logger.LogInformation(AuthLogEvents.TokenIssued,
                "签发访问令牌 subject={SubjectId} client={ClientId} scopes={Scopes} expires={ExpiresAt} jti={TokenId}",
                subject.Id, request.Client?.ClientId ?? subject.ClientId, string.Join(" ", request.Scopes), expiresAt, tokenId);

            return Task.FromResult(new IssuedToken
            {
                Token = token,
                TokenId = tokenId,
                ExpiresAt = expiresAt,
                ExpiresInSeconds = (int)lifetime.TotalSeconds,
            });
        }

        /// <inheritdoc/>
        public async Task<AccessTokenValidation> ValidateAccessTokenAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return AccessTokenValidation.Fail("empty_token");
            }

            TokenValidationResult result = await _handler.ValidateTokenAsync(accessToken, _validationParameters).ConfigureAwait(false);
            if (!result.IsValid)
            {
                string error = result.Exception?.GetType().Name ?? "invalid_token";
                _logger.LogDebug(AuthLogEvents.TokenValidationFailed, "令牌校验失败：{Error}", error);
                return AccessTokenValidation.Fail(error);
            }

            ClaimsIdentity identity = result.ClaimsIdentity;
            AuthSubject subject = AuthSubjectFactory.FromClaimsIdentity(identity);

            DateTimeOffset? expiresAt = null;
            string? tokenId = null;
            if (result.SecurityToken is JsonWebToken jwt)
            {
                expiresAt = jwt.ValidTo == DateTime.MinValue ? (DateTimeOffset?)null : new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero);
                tokenId = jwt.Id;
            }

            return new AccessTokenValidation
            {
                IsValid = true,
                Subject = subject,
                Principal = new ClaimsPrincipal(identity),
                ExpiresAt = expiresAt,
                TokenId = tokenId,
            };
        }

        /// <inheritdoc/>
        public string GetJwksJson() => _jwksJson;

        private string BuildJwksJson()
        {
            if (_rsaPublicParameters == null)
            {
                // 对称密钥不公开
                return "{\"keys\":[]}";
            }

            RSAParameters p = _rsaPublicParameters.Value;
            var jwks = new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "RSA",
                        use = "sig",
                        alg = "RS256",
                        kid = _keyId,
                        n = Base64Url.Encode(p.Modulus!),
                        e = Base64Url.Encode(p.Exponent!),
                    },
                },
            };
            return JsonSerializer.Serialize(jwks);
        }

        #region RSA 密钥管理

        private sealed class RsaKeyFile
        {
            public string Kty { get; set; } = "RSA";
            public string? N { get; set; }
            public string? E { get; set; }
            public string? D { get; set; }
            public string? P { get; set; }
            public string? Q { get; set; }
            public string? DP { get; set; }
            public string? DQ { get; set; }
            public string? QI { get; set; }
        }

        private RSAParameters LoadOrCreateRsaKey()
        {
            string path = _options.RsaKeyFilePath ?? Path.Combine(AppContext.BaseDirectory, "cyaim-auth-signing-key.json");

            if (File.Exists(path))
            {
                RsaKeyFile? file = JsonSerializer.Deserialize<RsaKeyFile>(File.ReadAllText(path));
                if (file?.N != null && file.E != null && file.D != null)
                {
                    return new RSAParameters
                    {
                        Modulus = Base64Url.Decode(file.N),
                        Exponent = Base64Url.Decode(file.E),
                        D = Base64Url.Decode(file.D!),
                        P = Base64Url.Decode(file.P!),
                        Q = Base64Url.Decode(file.Q!),
                        DP = Base64Url.Decode(file.DP!),
                        DQ = Base64Url.Decode(file.DQ!),
                        InverseQ = Base64Url.Decode(file.QI!),
                    };
                }
            }

            using RSA rsa = RSA.Create();
            EnsureKeySize(rsa);
            RSAParameters parameters = rsa.ExportParameters(true);

            var keyFile = new RsaKeyFile
            {
                N = Base64Url.Encode(parameters.Modulus!),
                E = Base64Url.Encode(parameters.Exponent!),
                D = Base64Url.Encode(parameters.D!),
                P = Base64Url.Encode(parameters.P!),
                Q = Base64Url.Encode(parameters.Q!),
                DP = Base64Url.Encode(parameters.DP!),
                DQ = Base64Url.Encode(parameters.DQ!),
                QI = Base64Url.Encode(parameters.InverseQ!),
            };

            string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(path, JsonSerializer.Serialize(keyFile, new JsonSerializerOptions { WriteIndented = true }));

            _logger.LogWarning(AuthLogEvents.DevSigningKeyGenerated,
                "已自动生成 RSA 签名密钥并保存到 {Path}。生产环境请妥善保管该文件或改用集中密钥管理。", path);

            return parameters;
        }

        private static void EnsureKeySize(RSA rsa)
        {
            if (rsa.KeySize < 2048)
            {
                rsa.KeySize = 2048;
            }
        }

        private static string ComputeKeyId(RSAParameters parameters)
        {
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(parameters.Modulus!);
            byte[] truncated = new byte[8];
            Array.Copy(hash, truncated, 8);
            return Base64Url.Encode(truncated);
        }

        #endregion
    }
}
