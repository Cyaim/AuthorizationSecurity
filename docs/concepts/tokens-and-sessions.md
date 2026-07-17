# 令牌与会话

> 一句话：Cyaim.Authentication 用 JWT 访问令牌承载身份与权限、用可轮换且能检测重放的刷新令牌维持长会话、用无状态签名 Cookie 实现 SSO，并以安全戳让凭据变更即时失效已签发令牌。

[文档中心](../README.md) / 概念

- 上一层概念：[架构总览](./architecture.md)、[权限模型](./permission-model.md)
- 相关参考：[OAuth2/OIDC 端点参考](../reference/server-endpoints.md)、[配置项参考](../reference/configuration.md)
- 相关指南：[搭建授权中心与统一登录](../guides/auth-server-sso.md)

## JWT 访问令牌

访问令牌由 `JwtTokenService`（`src/Cyaim.Authentication.Core/Tokens/JwtTokenService.cs`）签发与校验，遵循 RFC 7519 / RFC 9068 风格声明。

### 声明清单

`IssueAccessTokenAsync` 按需写入以下声明（声明名常量见 `src/Cyaim.Authentication.Abstractions/AuthConstants.cs` 的 `ClaimTypes`）：

| 声明 | 常量 | 来源 / 说明 |
| --- | --- | --- |
| `sub` | `Subject` | 主体Id（用户Id或客户端Id），始终写入 |
| `jti` | `TokenId` | 令牌唯一Id（`Guid` N 格式），始终写入 |
| `iss` | — | 签发者 = `Issuer`，由令牌描述符写入 |
| `aud` | — | 受众 = `Audience` |
| `iat` / `nbf` / `exp` | — | 签发 / 生效 / 过期时间（由令牌描述符写入） |
| `name` | `Name` | 主体显示名（非空时） |
| `preferred_username` | `PreferredUserName` | 用户名（主体 `Claims` 含此项时） |
| `client_id` | `ClientId` | 客户端Id（来自请求客户端或主体，非空时） |
| `sid` | `SessionId` | SSO 会话Id（非空时） |
| `sstamp` | `SecurityStamp` | 安全戳（主体 `Claims` 含此项时），框架私有声明 |
| `role` | `Role` | 角色名数组（`Roles` 非空时） |
| `scope` | `Scope` | 空格分隔的作用域字符串（RFC 9068 §2.2.3，`Scopes` 非空时） |
| `perm` | `Permission` | 权限代码数组，框架私有声明；仅当 `IncludePermissionClaims` 为真且提供 `PermissionCodes` 时写入 |

`perm` 声明让资源服务器能**离线**判断权限（无需回访授权中心或存储），代价是权限多时令牌变大；由 `CyaimAuthCoreOptions.IncludePermissionsInToken`（默认 `true`）与签发请求的 `IncludePermissionClaims` 控制。若资源服务器接了自己的用户/角色存储，评估器会以存储数据覆盖令牌声明（见[权限模型](./permission-model.md#编译buildentryasync)）。

校验（`ValidateAccessTokenAsync`）核对签名、有效期、`Issuer`、`Audience`，允许 `ClockSkew`（默认 30s）时钟偏移，成功后经 `AuthSubjectFactory.FromClaimsIdentity` 还原为 `AuthSubject`。

### HS256 vs RS256 与密钥来源

签名算法由是否配置 `CyaimAuthCoreOptions.HmacSigningKey` 决定（构造函数中固定一次）：

- **HS256（对称）**：配置了 `HmacSigningKey` 时启用。密钥须 ≥ 32 字节（UTF-8），否则构造抛 `InvalidOperationException`。签发与校验双方共享同一密钥，适合你同时掌控授权中心与资源服务器的场景。
- **RS256（非对称）**：未配置 `HmacSigningKey` 时启用。密钥从 `RsaKeyFilePath` 加载；文件不存在则自动生成 2048 位 RSA 并持久化（JSON 格式，含私钥参数），同时打一条 warning 提示生产环境妥善保管。资源服务器只需公钥（经 JWKS）即可校验，私钥不出授权中心。

```csharp
// HS256：共享密钥
builder.Services.AddCyaimAuthentication(o =>
{
    o.HmacSigningKey = "至少32字节的共享签名密钥..........";
}).AddInMemoryStore();

// RS256：留空 HmacSigningKey，指定密钥文件位置（省略则落在应用基目录）
builder.Services.AddCyaimAuthentication(o =>
{
    o.RsaKeyFilePath = "/var/secrets/cyaim-auth-signing-key.json";
}).AddInMemoryStore();
```

### JWKS

RS256 下，公钥经 JWKS 端点发布，资源服务器据此校验令牌。`GetJwksJson` 输出标准 JWK 集（`kty=RSA`、`use=sig`、`alg=RS256`、`kid`、`n`、`e`）；`kid` 由公钥模数 SHA-256 截断派生。HS256 下 JWKS 返回空 `keys` 数组（对称密钥不公开）。授权中心通过 `GET /.well-known/jwks` 暴露（见 [端点参考](../reference/server-endpoints.md)）；发现文档 `GET /.well-known/openid-configuration` 会给出 `jwks_uri`。

## 刷新令牌

刷新令牌用于在访问令牌过期后免登换取新访问令牌，由 `RefreshTokenManager`（`src/Cyaim.Authentication.Core/Tokens/RefreshTokenManager.cs`）管理，对齐 OAuth 2.0 Security BCP（RFC 9700 §4.14）。存储的是令牌哈希（`Base64URL(SHA-256(明文))`），明文只在签发响应里出现一次（`RefreshTokenRecord`，`src/Cyaim.Authentication.Abstractions/Models/TokenRecords.cs`）。

### 轮换（一次性使用）

每次兑换（`ExchangeAsync`）都**原子消费**旧令牌并签发同家族新令牌：

- 消费是存储层单次 check-then-set（`ConsumeRefreshTokenAsync`），杜绝并发下同一令牌被消费两次。
- 新令牌继承旧令牌的 `FamilyId` 与作用域，但**家族绝对过期时间不因轮换延长**（`newRecord.ExpiresAt = record.ExpiresAt`）。默认生命周期 `DefaultRefreshTokenLifetime` = 14 天。

### 家族重放吊销

一次性令牌被再次提交即视为泄露信号，触发整个家族吊销（RFC 9700 §4.14.2）：

- 兑换时若消费状态为 `AlreadyConsumed`（旧令牌重放，或并发的另一次兑换已抢先），调用 `RevokeRefreshTokenFamilyAsync(FamilyId)` 吊销整链并返回 `invalid_grant`（`replayDetected`）。
- 客户端Id 与记录不符也按泄露处理，吊销家族。
- 其他失败态返回 `invalid_grant`：`Revoked`（已吊销）、`Expired`（已过期）、`NotFound`（并发删除等）。

主动吊销：`RevokeAsync(refreshToken)` 吊销该令牌所在家族（RFC 7009，令牌不存在时静默成功）；`RevokeAllForSubjectAsync(subjectId, clientId?)` 吊销主体全部刷新令牌（登出、禁用账户时调用）。授权中心的 `POST /connect/revocation` 即走此路径。

## SSO 会话（签名 Cookie）

统一登录由 `SsoSessionService`（`src/Cyaim.Authentication.Server/Sso/SsoSessionService.cs`）实现，采用**无状态签名 Cookie**——服务端不存会话状态，凭签名保证不可伪造。

- **Cookie 格式**：`base64url(payload) + "|" + base64url(HMACSHA256(payload, key))`，`payload` 为 JSON `{sid, sub, name, authTime, expires}`。
- **签名密钥**：优先从 `HmacSigningKey` 派生（`HMACSHA256(key: HmacSigningKey, message: "sso-cookie")`）；未配置则自动生成 32 字节随机密钥并持久化到 `cyaim-sso-key.bin`（与 RSA 密钥同目录或应用基目录），并打 warning 提示生产建议配置 `HmacSigningKey`。
- **Cookie 属性**：`HttpOnly`、`SameSite=Lax`、`Path=/`，`Secure` 由 `SsoCookieSecurePolicy`（默认 `SameAsRequest`，即随请求是否 HTTPS）决定；Cookie 名 `SsoCookieName`（默认 `cyaim_sso`），有效期 `SsoSessionLifetime`（默认 8 小时）。
- **校验**（`Validate`）：用 `CryptographicOperations.FixedTimeEquals` 常量时间比对签名（防时序侧信道），再校验未过期，任一不符返回 `null`。
- **登出**（`Clear`）：删除该 Cookie。

浏览器持有有效 SSO Cookie 时，多个业务应用经 `/connect/authorize`（授权码 + PKCE，仅 S256）可免二次输入口令完成登录，共享同一会话。搭建见 [搭建授权中心与统一登录](../guides/auth-server-sso.md)。

## 安全戳失效机制

安全戳（`sstamp`）让「口令重置、账户禁用、授权重大变更」能**即时作废**已签发的访问令牌，无需维护令牌黑名单。

- **来源**：`AuthUser.SecurityStamp`（`src/Cyaim.Authentication.Abstractions/Models/AuthUser.cs`），默认随机 `Guid`；发生凭据/授权重大变更时更新它。
- **写入令牌**：签发时把当时的安全戳写入 `sstamp` 声明。
- **校验**：评估器构建用户权限集时（`PermissionEvaluator.BuildEntryAsync`），比对令牌 `sstamp` 与存储中用户当前 `SecurityStamp`；不一致即判定令牌失效，标记 `SubjectDisabled`（该主体权限集置空、判断返回 `SubjectDisabled`）。
- **缓存联动**：安全戳还是用户缓存键的一部分（`u|<Id>|<sstamp>`），旧令牌换新安全戳后不会命中旧缓存。

因此重置口令或收紧授权后更新安全戳，等价于让该用户此前所有访问令牌立刻失效——比等访问令牌自然过期更及时。对仅要求「已认证」的端点，中间件还会显式调用 `IsSubjectActiveAsync` 复核安全戳与启用/锁定状态（见[架构总览](./architecture.md#一次请求如何被鉴权)）。

## 口令哈希（PBKDF2）

口令由 `Pbkdf2PasswordHasher`（`src/Cyaim.Authentication.Core/Security/Pbkdf2PasswordHasher.cs`）哈希，PBKDF2-HMAC-SHA256（NIST SP 800-132）：

- **格式**：`PBKDF2-SHA256$迭代次数$盐Base64$哈希Base64`，参数自描述——可平滑升级迭代次数而不破坏旧哈希。
- **默认参数**：16 字节随机盐、32 字节派生密钥、迭代 100,000 次（可通过构造函数 `Pbkdf2PasswordHasher(int iterations)` 调整，下限 1000）。
- **校验**（`Verify`）：常量时间比较（`FixedTimeEquals`）防时序侧信道；并显式拒绝盐或哈希为空的退化哈希（防畸形/被篡改的空哈希导致任意口令通过）。
- 实现为 netstandard2.0 手写 PBKDF2，保证各目标框架行为一致。

替换口令哈希：注册自定义 `IPasswordHasher` 单例即可覆盖默认（`AddCyaimAuthCore` 用 `TryAddSingleton` 注册默认实现）。

```csharp
// 覆盖默认迭代次数
builder.Services.AddSingleton<IPasswordHasher>(new Pbkdf2PasswordHasher(iterations: 210_000));
```

暴力破解防护相关配置：`MaxAccessFailedCount`（默认 5）、`LockoutDuration`（默认 5 分钟），配合 `AuthUser.AccessFailedCount` / `LockoutEnd` 实现锁定。

## 相关文档

- [OAuth2/OIDC 端点参考](../reference/server-endpoints.md) —— `/connect/token`、`/connect/revocation`、JWKS 等
- [架构总览](./architecture.md) —— 令牌在请求管线中的位置
- [权限模型](./permission-model.md) —— `perm` 声明与有效权限编译
- [搭建授权中心与统一登录](../guides/auth-server-sso.md)
- [生产部署清单](../guides/production-checklist.md) —— 密钥管理与令牌生命周期
- [配置项参考](../reference/configuration.md) —— 令牌/会话相关配置默认值
