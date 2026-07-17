using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.AspNetCore;
using Cyaim.Authentication.Core.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Server.Sso
{
    /// <summary>
    /// 无状态签名 Cookie 的 SSO 会话服务。
    /// Cookie 值格式：base64url(payload) + "|" + base64url(HMACSHA256(payload, key))，
    /// payload 为 JSON {sid,sub,name,authTime,expires}。
    /// 密钥优先从 <see cref="Core.CyaimAuthCoreOptions.HmacSigningKey"/> 派生；
    /// 未配置时自动生成 32 字节随机密钥并持久化到 cyaim-sso-key.bin。
    /// </summary>
    public sealed class SsoSessionService
    {
        private const string KeyFileName = "cyaim-sso-key.bin";
        private const string KeyDerivationLabel = "sso-cookie";

        private readonly CyaimAuthServerOptions _serverOptions;
        private readonly IAuthClock _clock;
        private readonly ILogger<SsoSessionService> _logger;
        private readonly byte[] _key;

        /// <summary>创建服务并初始化 Cookie 签名密钥。</summary>
        public SsoSessionService(
            IOptions<CyaimAuthServerOptions> serverOptions,
            IOptions<CyaimAuthOptions> authOptions,
            IAuthClock clock,
            ILogger<SsoSessionService> logger)
        {
            _serverOptions = serverOptions.Value;
            _clock = clock;
            _logger = logger;
            _key = ResolveKey(authOptions.Value);
        }

        /// <summary>
        /// 签发 SSO 会话：写入签名 Cookie 并返回会话Id（sid）。
        /// </summary>
        public string Issue(HttpContext context, AuthUser user)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            DateTimeOffset now = _clock.UtcNow;
            DateTimeOffset expires = now + _serverOptions.SsoSessionLifetime;
            var payload = new SsoPayload
            {
                Sid = Guid.NewGuid().ToString("N"),
                Sub = user.Id,
                Name = user.DisplayName ?? user.UserName,
                AuthTime = now.ToUnixTimeSeconds(),
                Expires = expires.ToUnixTimeSeconds(),
            };

            byte[] payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload);
            string value = Base64Url.Encode(payloadBytes) + "|" + Base64Url.Encode(Sign(payloadBytes));

            bool secure = _serverOptions.SsoCookieSecurePolicy switch
            {
                CookieSecurePolicy.Always => true,
                CookieSecurePolicy.None => false,
                _ => context.Request.IsHttps, // SameAsRequest
            };
            context.Response.Cookies.Append(_serverOptions.SsoCookieName, value, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                Secure = secure,
                Expires = expires,
                Path = "/",
            });

            _logger.LogInformation(ServerLogEvents.SsoSessionIssued,
                "SSO 会话签发 sid={Sid} sub={SubjectId}", payload.Sid, payload.Sub);
            return payload.Sid;
        }

        /// <summary>
        /// 校验请求携带的 SSO Cookie；签名无效或过期返回 null。
        /// </summary>
        public SsoSession? Validate(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (!context.Request.Cookies.TryGetValue(_serverOptions.SsoCookieName, out string? value) ||
                string.IsNullOrEmpty(value))
            {
                return null;
            }

            int separator = value.IndexOf('|');
            if (separator <= 0 || separator == value.Length - 1)
            {
                return null;
            }

            byte[] payloadBytes;
            byte[] signature;
            try
            {
                payloadBytes = Base64Url.Decode(value.Substring(0, separator));
                signature = Base64Url.Decode(value.Substring(separator + 1));
            }
            catch (FormatException)
            {
                return null;
            }

            // 常量时间比较签名，防时序侧信道
            if (!CryptographicOperations.FixedTimeEquals(signature, Sign(payloadBytes)))
            {
                return null;
            }

            SsoPayload? payload;
            try
            {
                payload = JsonSerializer.Deserialize<SsoPayload>(payloadBytes);
            }
            catch (JsonException)
            {
                return null;
            }

            if (payload == null || string.IsNullOrEmpty(payload.Sid) || string.IsNullOrEmpty(payload.Sub))
            {
                return null;
            }

            if (DateTimeOffset.FromUnixTimeSeconds(payload.Expires) <= _clock.UtcNow)
            {
                return null;
            }

            return new SsoSession
            {
                Sid = payload.Sid,
                SubjectId = payload.Sub,
                Name = payload.Name,
                AuthTime = DateTimeOffset.FromUnixTimeSeconds(payload.AuthTime),
            };
        }

        /// <summary>
        /// 清除 SSO Cookie（登出）。
        /// </summary>
        public void Clear(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Cookies.Delete(_serverOptions.SsoCookieName, new CookieOptions { Path = "/" });
            _logger.LogInformation(ServerLogEvents.SsoSessionCleared, "SSO 会话 Cookie 已清除");
        }

        private byte[] Sign(byte[] payloadBytes)
        {
            using var hmac = new HMACSHA256(_key);
            return hmac.ComputeHash(payloadBytes);
        }

        private byte[] ResolveKey(CyaimAuthOptions authOptions)
        {
            // 优先从 HMAC 签名密钥派生：HMACSHA256(key: HmacSigningKey, message: "sso-cookie")
            if (!string.IsNullOrEmpty(authOptions.HmacSigningKey))
            {
                using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(authOptions.HmacSigningKey));
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(KeyDerivationLabel));
            }

            // 否则生成并持久化随机密钥（与 RSA 密钥同目录，或应用基目录）
            string? directory = null;
            if (!string.IsNullOrEmpty(authOptions.RsaKeyFilePath))
            {
                directory = Path.GetDirectoryName(Path.GetFullPath(authOptions.RsaKeyFilePath!));
            }
            if (string.IsNullOrEmpty(directory))
            {
                directory = AppContext.BaseDirectory;
            }

            string keyPath = Path.Combine(directory, KeyFileName);
            if (File.Exists(keyPath))
            {
                byte[] existing = File.ReadAllBytes(keyPath);
                if (existing.Length >= 32)
                {
                    return existing;
                }
            }

            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            Directory.CreateDirectory(directory!);
            File.WriteAllBytes(keyPath, key);
            _logger.LogWarning(ServerLogEvents.SsoKeyGenerated,
                "已自动生成 SSO Cookie 签名密钥并持久化到 {KeyPath}（生产环境建议配置 HmacSigningKey）", keyPath);
            return key;
        }

        /// <summary>
        /// Cookie 载荷（JSON 序列化格式）。
        /// </summary>
        private sealed class SsoPayload
        {
            /// <summary>会话Id</summary>
            [JsonPropertyName("sid")]
            public string Sid { get; set; } = string.Empty;

            /// <summary>主体Id</summary>
            [JsonPropertyName("sub")]
            public string Sub { get; set; } = string.Empty;

            /// <summary>显示名</summary>
            [JsonPropertyName("name")]
            public string? Name { get; set; }

            /// <summary>认证时间（Unix 秒）</summary>
            [JsonPropertyName("authTime")]
            public long AuthTime { get; set; }

            /// <summary>过期时间（Unix 秒）</summary>
            [JsonPropertyName("expires")]
            public long Expires { get; set; }
        }
    }

    /// <summary>
    /// 已验证的 SSO 会话。
    /// </summary>
    public sealed class SsoSession
    {
        /// <summary>会话Id</summary>
        public string Sid { get; set; } = string.Empty;

        /// <summary>主体Id</summary>
        public string SubjectId { get; set; } = string.Empty;

        /// <summary>显示名</summary>
        public string? Name { get; set; }

        /// <summary>认证时间</summary>
        public DateTimeOffset AuthTime { get; set; }
    }
}
