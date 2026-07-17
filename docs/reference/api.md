# 公开 API 参考

> 按包组织的 Cyaim.Authentication 2.0 公开类型速查：每个类型给出命名空间、用途与关键成员签名。面包屑：[文档中心](../README.md) / 参考

本页覆盖六个包的公开类型。签名均取自源码，可直接对照编译。配置项的逐条默认值见 [配置参考](configuration.md)；权限代码语法见 [权限代码参考](permission-codes.md)；判断原因与错误码见 [判断原因与错误码参考](decisions-and-errors.md)；OAuth2/OIDC 端点见 [服务器端点参考](server-endpoints.md)；管理 REST API 见 [管理 API 参考](admin-api.md)。

## 包与命名空间一览

| 包 | 主要命名空间 | 职责 |
|---|---|---|
| `Cyaim.Authentication.Abstractions` | `Cyaim.Authentication.Abstractions[.*]` | 契约、模型、权限匹配（ns2.0 零依赖） |
| `Cyaim.Authentication.Core` | `Cyaim.Authentication.Core[.*]`、`Microsoft.Extensions.DependencyInjection` | 权限引擎、JWT、存储、审计 |
| `Cyaim.Authentication` | `Cyaim.Authentication.AspNetCore`、`Microsoft.AspNetCore.*`、`Microsoft.Extensions.DependencyInjection` | ASP.NET Core 集成 |
| `Cyaim.Authentication.Server` | `Cyaim.Authentication.Server[.*]`、`Microsoft.AspNetCore.Builder` | OAuth2/OIDC 授权中心、SSO |
| `Cyaim.Authentication.AdminPanel` | `Cyaim.Authentication.AdminPanel`、`Microsoft.AspNetCore.Builder` | 权限管理面板 |
| `Cyaim.Authentication.Client` | `Cyaim.Authentication.Client` | 客户端 SDK |

> 约定：DI 扩展方法刻意放在 `Microsoft.Extensions.DependencyInjection` / `Microsoft.AspNetCore.Builder` 命名空间下，`using` 常见宿主命名空间即可发现，无需额外 `using`。

---

# Cyaim.Authentication.Abstractions

契约层。目标框架 `netstandard2.0`，零第三方依赖，可被桌面/WASM/控制台等任意宿主引用。

## AuthConstants

`Cyaim.Authentication.Abstractions` · 框架级常量：声明类型、授权类型、作用域、端点路径、内置管理权限。

```csharp
public static class AuthConstants
{
    public const string SchemeName    = "CyaimAuth";
    public const string AllPermissions = "**";
    public const string GuestSubjectId = "sys_guest";
}
```

嵌套常量类：

```csharp
// AuthConstants.ClaimTypes —— 标准/框架私有声明名
public const string Subject           = "sub";
public const string PreferredUserName = "preferred_username";
public const string Name              = "name";
public const string Role              = "role";
public const string Permission        = "perm";     // 框架私有
public const string Scope             = "scope";
public const string ClientId          = "client_id";
public const string SessionId         = "sid";
public const string Issuer            = "iss";
public const string Audience          = "aud";
public const string TokenId           = "jti";
public const string AuthTime          = "auth_time";
public const string Email             = "email";
public const string SecurityStamp     = "sstamp";   // 框架私有

// AuthConstants.GrantTypes —— OAuth 2.0 授权类型
public const string AuthorizationCode = "authorization_code";
public const string ClientCredentials = "client_credentials";
public const string Password          = "password";
public const string RefreshToken      = "refresh_token";

// AuthConstants.Scopes
public const string OpenId        = "openid";
public const string Profile       = "profile";
public const string OfflineAccess = "offline_access";
public const string Permissions   = "permissions";

// AuthConstants.Endpoints —— 默认端点路径
public const string Discovery  = "/.well-known/openid-configuration";
public const string Jwks       = "/.well-known/jwks";
public const string Token      = "/connect/token";
public const string Authorize  = "/connect/authorize";
public const string Introspect = "/connect/introspect";
public const string Revoke     = "/connect/revocation";
public const string UserInfo   = "/connect/userinfo";
public const string EndSession = "/connect/endsession";
public const string Login      = "/account/login";
public const string Logout     = "/account/logout";
public const string AdminPanel = "/auth-admin";

// AuthConstants.AdminPermissions —— 内置管理权限代码
public const string All               = "auth.admin.**";
public const string Read              = "auth.admin.read";
public const string ManageUsers       = "auth.admin.users";
public const string ManageRoles       = "auth.admin.roles";
public const string ManagePermissions = "auth.admin.permissions";
public const string ManageClients     = "auth.admin.clients";
public const string ReadAudit         = "auth.admin.audit";
```

## 权限匹配（Permissions）

### PermissionCode

`Cyaim.Authentication.Abstractions.Permissions` · 权限代码规范化与语法校验（静态）。

```csharp
public static class PermissionCode
{
    public const char   Separator      = '.';   // 规范分隔符
    public const char   AltSeparator   = ':';   // 等价分隔符（规范化为 '.'）
    public const string SingleWildcard = "*";    // 匹配恰一段
    public const string MultiWildcard  = "**";   // 匹配零或多段，仅限末段

    public static string  Normalize(string code);              // 非法抛 ArgumentException
    public static bool    TryNormalize(string code, out string normalized);
    public static bool    TryNormalize(string code, out string normalized, out string? error);
    public static string[] Split(string normalizedCode);
    public static bool    HasWildcard(string normalizedCode);
}
```

规则：段间 `.` 与 `:` 等价、大小写不敏感；`*` 匹配恰一段，`**` 匹配零或多段且仅允许作末段。详见 [权限代码参考](permission-codes.md)。

### PermissionQuery

`Cyaim.Authentication.Abstractions.Permissions` · 预解析的权限查询（`readonly struct`），对固定代码解析一次，检查时零解析开销。

```csharp
public readonly struct PermissionQuery : IEquatable<PermissionQuery>
{
    public string   Code     { get; }
    public string[] Segments { get; }
    public bool     IsEmpty  { get; }

    public static PermissionQuery Parse(string code);            // 非法抛 ArgumentException
    public static bool TryParse(string code, out PermissionQuery query);
}
```

### PermissionEffect

`Cyaim.Authentication.Abstractions.Permissions` · 单次匹配效果枚举，拒绝优先（Deny-Override）。

```csharp
public enum PermissionEffect { NotSet = 0, Allow = 1, Deny = 2 }
```

### CompiledPermissionSet

`Cyaim.Authentication.Abstractions.Permissions` · 编译后的主体权限集，构建一次、查询 O(1)（精确）/ O(段数)（通配符），构建后不可变、线程安全。

```csharp
public sealed class CompiledPermissionSet
{
    public static readonly CompiledPermissionSet Empty;

    public long                  StoreVersion { get; }   // 缓存失效判断
    public IReadOnlyList<string> Allows       { get; }
    public IReadOnlyList<string> Denies       { get; }

    public static CompiledPermissionSet Build(
        IEnumerable<string> allowCodes,
        IEnumerable<string>? denyCodes = null,
        long storeVersion = 0);                            // 非法代码被忽略（只收紧不阻断）

    public bool            IsGranted(in PermissionQuery query);
    public bool            IsGranted(string permissionCode);
    public PermissionEffect Evaluate(string permissionCode);
    public PermissionEffect Evaluate(in PermissionQuery query);
}
```

## 模型（Models）

### AuthUser

`Cyaim.Authentication.Abstractions.Models` · 存储中的用户账户。

```csharp
public class AuthUser
{
    public string Id           { get; set; } = Guid.NewGuid().ToString("N");
    public string UserName     { get; set; }             // 唯一，不区分大小写
    public string? DisplayName { get; set; }
    public string? Email       { get; set; }
    public string? PasswordHash { get; set; }            // IPasswordHasher 生成
    public bool   IsEnabled    { get; set; } = true;
    public DateTimeOffset? LockoutEnd { get; set; }
    public int    AccessFailedCount   { get; set; }
    public string SecurityStamp       { get; set; } = Guid.NewGuid().ToString("N");
    public List<string> Roles              { get; set; } = new();
    public List<string> DirectPermissions  { get; set; } = new();
    public List<string> DeniedPermissions  { get; set; } = new();  // 优先于任何允许
    public Dictionary<string, string> Claims { get; set; } = new();
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public bool     IsLockedOut(DateTimeOffset now);
    public AuthUser Clone();                              // 深拷贝，存储读写隔离
}
```

### AuthRole

`Cyaim.Authentication.Abstractions.Models` · 角色（RBAC），支持父角色层级继承（NIST RBAC1），环安全忽略。

```csharp
public class AuthRole
{
    public string Id          { get; set; } = Guid.NewGuid().ToString("N");
    public string Name        { get; set; }              // 唯一，不区分大小写
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public List<string> ParentRoles       { get; set; } = new();  // 继承其权限
    public List<string> Permissions       { get; set; } = new();
    public List<string> DeniedPermissions { get; set; } = new();
    public bool   IsSystem  { get; set; }                // 内置角色不可删除
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public AuthRole Clone();
}
```

### ClientApplication

`Cyaim.Authentication.Abstractions.Models` · 已注册的 OAuth 2.0 客户端应用（RFC 6749 §2）。

```csharp
public class ClientApplication
{
    public string  ClientId          { get; set; }
    public string? ClientName        { get; set; }
    public string? ClientSecretHash  { get; set; }       // 公共客户端可为空
    public List<string> AllowedGrantTypes       { get; set; } = new();
    public List<string> RedirectUris            { get; set; } = new();  // 精确匹配
    public List<string> PostLogoutRedirectUris  { get; set; } = new();
    public List<string> AllowedScopes           { get; set; } = new();
    public bool RequirePkce         { get; set; } = true;
    public bool AllowOfflineAccess  { get; set; }
    public List<string> Permissions { get; set; } = new(); // client_credentials 授予的权限
    public int  AccessTokenLifetimeSeconds        { get; set; } = 3600;
    public int  RefreshTokenLifetimeSeconds       { get; set; } = 14 * 24 * 3600;
    public int  AuthorizationCodeLifetimeSeconds  { get; set; } = 300;
    public bool Enabled { get; set; } = true;
    public List<string> AllowedCorsOrigins { get; set; } = new(); // 仅记录，框架不下发 CORS 头
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
```

### PermissionDefinition

`Cyaim.Authentication.Abstractions.Models` · 可被授予的权限节点定义（供管理面板展示与分配）。

```csharp
public class PermissionDefinition
{
    public string  Code        { get; set; }             // 规范化，如 sys.user.read
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public string? Group       { get; set; }             // 通常为模块名
    public PermissionOrigin Origin { get; set; } = PermissionOrigin.Manual;
    public DateTimeOffset   CreatedAt { get; set; }
}

public enum PermissionOrigin { Manual = 0, EndpointDiscovery = 1, System = 2 }
```

### AuthSubject / AuthSubjectType

`Cyaim.Authentication.Abstractions.Models` · 一次权限判断的对象（用户、客户端或游客），由令牌/会话解析得到，不含凭据。

```csharp
public class AuthSubject
{
    public string  Id   { get; set; } = string.Empty;
    public string? Name { get; set; }
    public bool    IsAuthenticated { get; set; }         // 游客为 false
    public AuthSubjectType SubjectType { get; set; } = AuthSubjectType.User;
    public IReadOnlyList<string> Roles             { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> DirectPermissions { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> DeniedPermissions { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> Scopes            { get; set; } = Array.Empty<string>();
    public string? ClientId  { get; set; }
    public string? SessionId { get; set; }
    public IReadOnlyDictionary<string, string> Claims { get; set; }

    public static AuthSubject Guest(IReadOnlyList<string>? guestRoles = null);
}

public enum AuthSubjectType { User = 0, Client = 1, Guest = 2 }
```

### AuditEvent / AuditCategory / AuditOutcome

`Cyaim.Authentication.Abstractions.Models` · 审计事件与其分类枚举。

```csharp
public class AuditEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTimeOffset Timestamp { get; set; }
    public AuditCategory  Category  { get; set; }
    public AuditOutcome   Outcome   { get; set; }
    public string? SubjectId   { get; set; }
    public string? SubjectName { get; set; }
    public string? ClientId    { get; set; }
    public string? Resource    { get; set; }   // 端点路径/权限代码/被管理对象Id
    public string? Action      { get; set; }
    public string? Detail      { get; set; }
    public string? RemoteIp    { get; set; }
}

public enum AuditCategory { Login = 0, Logout = 1, TokenIssued = 2, TokenRevoked = 3,
                            PermissionCheck = 4, Admin = 5, Security = 6 }
public enum AuditOutcome  { Success = 0, Denied = 1, Failure = 2 }
```

### RefreshTokenRecord / AuthorizationCodeRecord

`Cyaim.Authentication.Abstractions.Models` · 令牌与授权码记录，均存哈希不存明文。

```csharp
public class RefreshTokenRecord
{
    public string TokenHash { get; set; }                // Base64URL(SHA-256(明文))
    public string FamilyId  { get; set; } = Guid.NewGuid().ToString("N"); // 轮换链，重放整链吊销
    public string SubjectId { get; set; }
    public string ClientId  { get; set; }
    public List<string> Scopes { get; set; } = new();
    public string? SessionId   { get; set; }
    public DateTimeOffset  CreatedAt  { get; set; }
    public DateTimeOffset  ExpiresAt  { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }      // 轮换后置位；再次使用即重放
    public DateTimeOffset? RevokedAt  { get; set; }

    public bool IsActive(DateTimeOffset now);
}

public class AuthorizationCodeRecord
{
    public string CodeHash    { get; set; }              // 一次性
    public string ClientId    { get; set; }
    public string SubjectId   { get; set; }
    public string RedirectUri { get; set; }              // 兑换时必须一致
    public List<string> Scopes { get; set; } = new();
    public string? CodeChallenge       { get; set; }     // PKCE
    public string? CodeChallengeMethod { get; set; }     // S256 / plain
    public string? Nonce      { get; set; }
    public string? SessionId  { get; set; }
    public DateTimeOffset  CreatedAt  { get; set; }
    public DateTimeOffset  ExpiresAt  { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
}
```

## 授权（Authorization）

### AuthorizationDecision / AuthorizationReason

`Cyaim.Authentication.Abstractions.Authorization` · 权限判断结论（不可变），含可诊断原因。

```csharp
public sealed class AuthorizationDecision
{
    public bool             IsGranted      { get; }
    public PermissionEffect Effect         { get; }
    public AuthorizationReason Reason      { get; }
    public string?          PermissionCode { get; }
    public string?          PolicyName     { get; }

    public static AuthorizationDecision Granted(AuthorizationReason reason,
        string? permissionCode = null, string? policyName = null);
    public static AuthorizationDecision Denied(AuthorizationReason reason,
        string? permissionCode = null, string? policyName = null);
}

public enum AuthorizationReason
{
    Granted = 0, GrantedByPolicy = 1, NotProtected = 2, GuestAllowed = 3,
    NoMatchingGrant = 10, DeniedByRule = 11, GuestNotAllowed = 12, SubjectDisabled = 13,
    PolicyNotSatisfied = 14, PolicyNotFound = 15, InvalidPermissionCode = 16, InvalidCredential = 17,
}
```

各原因的语义与对应 HTTP 响应见 [判断原因与错误码参考](decisions-and-errors.md)。

### AuthorizationContext / IAuthPolicy

`Cyaim.Authentication.Abstractions.Authorization` · ABAC 策略评估上下文与策略契约。

```csharp
public class AuthorizationContext
{
    public AuthSubject Subject        { get; set; } = AuthSubject.Guest();
    public string?     PermissionCode { get; set; }
    public IDictionary<string, object?> Items { get; }   // 大小写不敏感键
    public object?          UnderlyingContext { get; set; } // ASP.NET Core 下为 HttpContext
    public DateTimeOffset   Now { get; set; }
}

public interface IAuthPolicy
{
    string Name { get; }                                 // 唯一，不区分大小写
    Task<bool> EvaluateAsync(AuthorizationContext context, CancellationToken cancellationToken = default);
}
```

自定义策略写法见 [自定义 ABAC 策略](../guides/custom-policies.md)。

## 服务契约（Services）

### IPermissionEvaluator（+ 扩展）

`Cyaim.Authentication.Abstractions.Services` · 鉴权核心入口，缓存每主体的编译权限集。

```csharp
public interface IPermissionEvaluator
{
    Task<CompiledPermissionSet> GetPermissionSetAsync(AuthSubject subject, CancellationToken ct = default);
    bool TryGetCachedPermissionSet(AuthSubject subject, out CompiledPermissionSet permissionSet);
    Task<bool> IsSubjectActiveAsync(AuthSubject subject, CancellationToken ct = default);
    Task<AuthorizationDecision> EvaluateAsync(AuthSubject subject, PermissionQuery permission,
        AuthorizationContext? context = null, CancellationToken ct = default);
    Task<AuthorizationDecision> EvaluatePolicyAsync(AuthSubject subject, string policyName,
        AuthorizationContext? context = null, CancellationToken ct = default);
}

// PermissionEvaluatorExtensions —— 以字符串代码为参数的便捷重载
public static Task<AuthorizationDecision> EvaluateAsync(this IPermissionEvaluator evaluator,
    AuthSubject subject, string permissionCode, AuthorizationContext? context = null, CancellationToken ct = default);
public static Task<bool> IsGrantedAsync(this IPermissionEvaluator evaluator,
    AuthSubject subject, string permissionCode, CancellationToken ct = default);
```

### ITokenService（+ 请求/结果 DTO）

`Cyaim.Authentication.Abstractions.Services` · 签发与校验 JWT 访问令牌、导出 JWKS。

```csharp
public interface ITokenService
{
    string Issuer { get; }
    Task<IssuedToken>          IssueAccessTokenAsync(AccessTokenRequest request, CancellationToken ct = default);
    Task<AccessTokenValidation> ValidateAccessTokenAsync(string accessToken, CancellationToken ct = default);
    string GetJwksJson();                                // 对称密钥时返回空 keys 数组
}

public class AccessTokenRequest
{
    public AuthSubject Subject { get; set; } = AuthSubject.Guest();
    public ClientApplication? Client { get; set; }
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();
    public TimeSpan? Lifetime { get; set; }
    public bool IncludePermissionClaims { get; set; }
    public IReadOnlyList<string>? PermissionCodes { get; set; }
    public IDictionary<string, string>? ExtraClaims { get; set; }
}

public class IssuedToken
{
    public string Token { get; set; }
    public string TokenId { get; set; }                  // jti
    public DateTimeOffset ExpiresAt { get; set; }
    public int ExpiresInSeconds { get; set; }
}

public class AccessTokenValidation
{
    public bool IsValid { get; set; }
    public string? Error { get; set; }
    public AuthSubject? Subject { get; set; }
    public ClaimsPrincipal? Principal { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public string? TokenId { get; set; }
    public static AccessTokenValidation Fail(string error);
}
```

### IPasswordHasher

`Cyaim.Authentication.Abstractions.Services` · 用户口令与客户端密钥的哈希（含盐、自验证、常量时间比较）。

```csharp
public interface IPasswordHasher
{
    string Hash(string password);
    bool   Verify(string hash, string password);
}
```

### IAuditLogger（+ AuditQuery）

`Cyaim.Authentication.Abstractions.Services` · 审计写入与查询。

```csharp
public interface IAuditLogger
{
    Task WriteAsync(AuditEvent auditEvent, CancellationToken ct = default);  // 不应抛异常阻断业务
    Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken ct = default);
}

public class AuditQuery
{
    public DateTimeOffset? From { get; set; }
    public DateTimeOffset? To   { get; set; }
    public AuditCategory?  Category { get; set; }
    public AuditOutcome?   Outcome  { get; set; }
    public string?         SubjectId { get; set; }
    public int Skip { get; set; }
    public int Take { get; set; } = 100;                 // 上限 1000
}
```

### IAuthClock

`Cyaim.Authentication.Abstractions.Services` · 时钟抽象，令牌有效期/锁定判断可测试化。

```csharp
public interface IAuthClock { DateTimeOffset UtcNow { get; } }
```

## 存储接口（Stores）

`Cyaim.Authentication.Abstractions.Stores` · 六个存储契约，可分别实现，或用一个类实现全部经 `MapStore<T>` 注册（单例）。EF/DbContext 实现须在内部用 `IDbContextFactory`/`IServiceScopeFactory` 自建作用域——详见 [自定义存储](../guides/custom-stores.md)。

```csharp
public interface IUserStore
{
    Task<AuthUser?> FindByIdAsync(string id, CancellationToken ct = default);
    Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken ct = default);
    Task CreateAsync(AuthUser user, CancellationToken ct = default);
    Task UpdateAsync(AuthUser user, CancellationToken ct = default);
    Task DeleteAsync(string id, CancellationToken ct = default);
    Task<IReadOnlyList<AuthUser>> ListAsync(string? search, int skip, int take, CancellationToken ct = default);
    Task<int> CountAsync(string? search, CancellationToken ct = default);
}

public interface IRoleStore
{
    Task<AuthRole?> FindByIdAsync(string id, CancellationToken ct = default);
    Task<AuthRole?> FindByNameAsync(string name, CancellationToken ct = default);
    Task<IReadOnlyList<AuthRole>> GetAllAsync(CancellationToken ct = default);
    Task CreateAsync(AuthRole role, CancellationToken ct = default);
    Task UpdateAsync(AuthRole role, CancellationToken ct = default);
    Task DeleteAsync(string id, CancellationToken ct = default);
}

public interface IClientStore
{
    Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken ct = default);
    Task<IReadOnlyList<ClientApplication>> GetAllAsync(CancellationToken ct = default);
    Task CreateAsync(ClientApplication client, CancellationToken ct = default);
    Task UpdateAsync(ClientApplication client, CancellationToken ct = default);
    Task DeleteAsync(string clientId, CancellationToken ct = default);
}

public interface IPermissionDefinitionStore
{
    Task UpsertAsync(IEnumerable<PermissionDefinition> definitions, CancellationToken ct = default);
    Task<IReadOnlyList<PermissionDefinition>> GetAllAsync(CancellationToken ct = default);
    Task DeleteAsync(string code, CancellationToken ct = default);
}

public interface ITokenStore
{
    Task SaveRefreshTokenAsync(RefreshTokenRecord record, CancellationToken ct = default);
    Task<RefreshTokenRecord?> FindRefreshTokenAsync(string tokenHash, CancellationToken ct = default);
    Task UpdateRefreshTokenAsync(RefreshTokenRecord record, CancellationToken ct = default);
    Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(string tokenHash, DateTimeOffset now, CancellationToken ct = default);
    Task RevokeRefreshTokenFamilyAsync(string familyId, CancellationToken ct = default);
    Task RevokeSubjectRefreshTokensAsync(string subjectId, string? clientId = null, CancellationToken ct = default);
    Task RevokeClientRefreshTokensAsync(string clientId, CancellationToken ct = default);
    Task SaveAuthorizationCodeAsync(AuthorizationCodeRecord record, CancellationToken ct = default);
    Task<AuthorizationCodeRecord?> ConsumeAuthorizationCodeAsync(string codeHash, CancellationToken ct = default);
    Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken ct = default);
}

public interface IAuthStoreVersion
{
    long Version { get; }
    void Bump();
    event Action<long>? Changed;
}
```

`ConsumeRefreshTokenAsync` 返回的结果类型：

```csharp
public readonly struct RefreshTokenConsumeResult
{
    public RefreshTokenConsumeStatus Status { get; }
    public RefreshTokenRecord?       Record { get; }     // NotFound 时为 null
    public RefreshTokenConsumeResult(RefreshTokenConsumeStatus status, RefreshTokenRecord? record);
}

public enum RefreshTokenConsumeStatus { Consumed = 0, NotFound = 1, AlreadyConsumed = 2, Revoked = 3, Expired = 4 }
```

## 特性（Attributes）

### RequirePermissionAttribute

`Cyaim.Authentication.Abstractions` · 声明访问所需权限；可用于类/方法/属性/字段，可多次标注（`AllowMultiple = true, Inherited = true`）。

```csharp
public class RequirePermissionAttribute : Attribute
{
    public RequirePermissionAttribute(params string[] permissionCodes); // 空数组 = 仅要求已认证
    public string[] PermissionCodes { get; }
    public bool     RequireAll      { get; set; }        // true=全部满足；false（默认）=任一满足
    public string?  Policy          { get; set; }        // 附加 ABAC 策略名
}
```

多个特性之间为「且」；单特性内多个代码默认「或」，`RequireAll = true` 改为「且」。

### AllowGuestAttribute

`Cyaim.Authentication.Abstractions` · 允许游客访问，覆盖上层权限要求（类/方法级）。

```csharp
public class AllowGuestAttribute : Attribute { }
```

---

# Cyaim.Authentication.Core

权限引擎、JWT 令牌、内置存储、审计的默认实现。

## CyaimAuthCoreOptions

`Cyaim.Authentication.Core` · 核心引擎配置。逐项默认值见 [配置参考](configuration.md)。

```csharp
public class CyaimAuthCoreOptions
{
    public string  Issuer   { get; set; } = "cyaim-auth";
    public string  Audience { get; set; } = "cyaim-api";
    public string? HmacSigningKey { get; set; }          // HS256，≥32 字节；空则用 RSA
    public string? RsaKeyFilePath { get; set; }          // RS256 密钥持久化路径
    public TimeSpan DefaultAccessTokenLifetime  { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan DefaultRefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);
    public List<string> GuestRoles { get; set; } = new();
    public TimeSpan PermissionCacheTtl { get; set; } = TimeSpan.FromMinutes(5);
    public int  MaxCachedPermissionSets { get; set; } = 10_000;
    public bool IncludePermissionsInToken { get; set; } = true;
    public int  AuditCapacity { get; set; } = 5000;
    public string? AuditFilePath { get; set; }
    public int  MaxAccessFailedCount { get; set; } = 5;
    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(5);
}
```

## AddCyaimAuthCore / CyaimAuthCoreBuilder

`Microsoft.Extensions.DependencyInjection` · 注册核心服务并返回链式构建器（仅核心引擎、无 ASP.NET Core 时用；ASP.NET Core 宿主用 `AddCyaimAuthentication`）。

```csharp
public static CyaimAuthCoreBuilder AddCyaimAuthCore(
    this IServiceCollection services, Action<CyaimAuthCoreOptions>? configure = null);

public sealed class CyaimAuthCoreBuilder
{
    public IServiceCollection Services { get; }

    public CyaimAuthCoreBuilder AddInMemoryStore();
    public CyaimAuthCoreBuilder AddJsonFileStore(string filePath);
    public CyaimAuthCoreBuilder MapStore<TStore>()
        where TStore : class, IUserStore, IRoleStore, IClientStore,
                       IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion;
    public CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, bool> evaluate);
    public CyaimAuthCoreBuilder AddPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate);
    public CyaimAuthCoreBuilder AddPolicy<TPolicy>() where TPolicy : class, IAuthPolicy;
}
```

注册的默认实现：`IAuthClock`→`SystemAuthClock`、`IPasswordHasher`→`Pbkdf2PasswordHasher`、`IPermissionEvaluator`→`PermissionEvaluator`、`ITokenService`→`JwtTokenService`、`IAuditLogger`→`DefaultAuditLogger`，以及 `RefreshTokenManager`、`UserCredentialService`、`AuthDataSeeder`（均单例）。

## PermissionEvaluator

`Cyaim.Authentication.Core.Engine` · `IPermissionEvaluator` 默认实现，缓存编译权限集，存储版本变化或 TTL 到期时重建。

```csharp
public sealed class PermissionEvaluator : IPermissionEvaluator
{
    public PermissionEvaluator(IOptions<CyaimAuthCoreOptions> options, IAuthClock clock,
        ILogger<PermissionEvaluator> logger, AuthPolicyRegistry policies, IServiceProvider serviceProvider);

    public void InvalidateAll();                         // 立即清空全部缓存
    // 其余成员见 IPermissionEvaluator
}
```

## JwtTokenService

`Cyaim.Authentication.Core.Tokens` · `ITokenService` 默认实现（RFC 7519 / RFC 9068 风格声明）。配置 `HmacSigningKey` 用 HS256，否则用 RS256（密钥自动生成并持久化）。

```csharp
public sealed class JwtTokenService : ITokenService
{
    public JwtTokenService(IOptions<CyaimAuthCoreOptions> options, IAuthClock clock, ILogger<JwtTokenService> logger);
    public string Issuer { get; }
    // 成员见 ITokenService
}
```

## RefreshTokenManager

`Cyaim.Authentication.Core.Tokens` · 刷新令牌签发/轮换/吊销，检测重放时吊销整个家族。

```csharp
public sealed class RefreshTokenManager
{
    public RefreshTokenManager(ITokenStore tokenStore, IAuthClock clock,
        IOptions<CyaimAuthCoreOptions> options, ILogger<RefreshTokenManager> logger);

    public Task<(string Token, RefreshTokenRecord Record)> IssueAsync(
        string subjectId, string clientId, IEnumerable<string> scopes,
        string? sessionId = null, TimeSpan? lifetime = null, CancellationToken ct = default);
    public Task<RefreshExchangeResult> ExchangeAsync(string refreshToken, string clientId, CancellationToken ct = default);
    public Task RevokeAsync(string refreshToken, CancellationToken ct = default);
    public Task RevokeAllForSubjectAsync(string subjectId, string? clientId = null, CancellationToken ct = default);
}

public sealed class RefreshExchangeResult
{
    public bool    Success        { get; }
    public string? Error          { get; }
    public string? ErrorDescription { get; }
    public bool    ReplayDetected { get; }
    public string? NewToken       { get; }
    public RefreshTokenRecord? Record { get; }
}
```

## Pbkdf2PasswordHasher

`Cyaim.Authentication.Core.Security` · `IPasswordHasher` 默认实现，PBKDF2-HMAC-SHA256（NIST SP 800-132），哈希格式 `PBKDF2-SHA256$迭代次数$盐$哈希`，参数自描述。

```csharp
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    public Pbkdf2PasswordHasher();                       // 默认 100,000 次迭代
    public Pbkdf2PasswordHasher(int iterations);         // <1000 抛 ArgumentOutOfRangeException
    public string Hash(string password);
    public bool   Verify(string hash, string password);
}
```

## TokenHasher

`Cyaim.Authentication.Core.Security` · 不透明令牌（刷新令牌/授权码）生成与哈希（静态）。

```csharp
public static class TokenHasher
{
    public static string CreateToken(int byteLength = 32);   // Base64URL 随机
    public static string HashToken(string token);            // Base64URL(SHA-256(UTF8(token)))
}
```

## InMemoryAuthStore

`Cyaim.Authentication.Core.Stores` · 六存储接口的内存实现（测试、示例、小型部署），经 `AddInMemoryStore()` 注册。

```csharp
public class InMemoryAuthStore
    : IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion
{ /* 实现全部存储接口成员 */ }
```

## JsonFileAuthStore

`Cyaim.Authentication.Core.Stores` · JSON 文件持久化存储，继承 `InMemoryAuthStore`，写入去抖动，经 `AddJsonFileStore(path)` 注册。

```csharp
public sealed class JsonFileAuthStore : InMemoryAuthStore, IDisposable
{
    public JsonFileAuthStore(string filePath, int debounceMilliseconds = 500);
}
```

## AuthDataSeeder

`Cyaim.Authentication.Core` · 幂等种子数据（存在则不修改）。

```csharp
public sealed class AuthDataSeeder
{
    public Task<AuthRole> EnsureRoleAsync(string name,
        IEnumerable<string>? permissions = null, IEnumerable<string>? parentRoles = null,
        IEnumerable<string>? deniedPermissions = null, string? displayName = null,
        bool isSystem = false, CancellationToken ct = default);

    public Task<AuthUser> EnsureUserAsync(string userName, string password,
        IEnumerable<string>? roles = null, IEnumerable<string>? directPermissions = null,
        string? displayName = null, string? email = null, CancellationToken ct = default);

    public Task<ClientApplication> EnsureClientAsync(string clientId, string? clientSecret,
        IEnumerable<string> allowedGrantTypes, IEnumerable<string>? allowedScopes = null,
        IEnumerable<string>? redirectUris = null, IEnumerable<string>? permissions = null,
        bool allowOfflineAccess = false, string? clientName = null, bool requirePkce = true,
        IEnumerable<string>? postLogoutRedirectUris = null, CancellationToken ct = default);

    public Task EnsurePermissionDefinitionsAsync(
        IEnumerable<(string Code, string? DisplayName, string? Group)> definitions, CancellationToken ct = default);
}
```

## UserCredentialService

`Cyaim.Authentication.Core.Security` · 用户名口令校验，含锁定与计时侧信道防护。

```csharp
public sealed class UserCredentialService
{
    public Task<CredentialValidationResult> ValidateAsync(
        string userName, string password, string? remoteIp = null, CancellationToken ct = default);
}

public sealed class CredentialValidationResult
{
    public bool      Success { get; }
    public string?   Error   { get; }
    public AuthUser? User    { get; }
}
```

## DefaultAuditLogger

`Cyaim.Authentication.Core.Audit` · `IAuditLogger` 默认实现，环形内存缓冲 + 可选 JSONL 落盘。

```csharp
public sealed class DefaultAuditLogger : IAuditLogger, IDisposable
{
    public DefaultAuditLogger(IOptions<CyaimAuthCoreOptions> options, ILogger<DefaultAuditLogger> logger);
    // 成员见 IAuditLogger + Dispose()
}
```

## AuthMetrics

`Cyaim.Authentication.Core.Engine` · 框架指标（`System.Diagnostics.Metrics`，可接 OpenTelemetry / dotnet-counters），Meter 名称 `Cyaim.Authentication`。

```csharp
public static class AuthMetrics
{
    public const string MeterName = "Cyaim.Authentication";
    public static void RecordCheck(bool granted, bool cacheHit, double elapsedMs);
    public static void RecordTokenIssued(string grantOrKind);
}
```

采集的仪表：`cyaim_auth.permission_checks`、`permission_denials`、`permission_set_cache_hits`、`permission_set_cache_misses`、`check_duration`（ms 直方图）、`tokens_issued`。

## AuthLogEvents

`Cyaim.Authentication.Core` · 结构化日志的 `EventId` 常量（供日志过滤）。

```csharp
public static class AuthLogEvents
{
    public static readonly EventId PermissionDenied;        // 2001
    public static readonly EventId PermissionSetBuilt;      // 2002
    public static readonly EventId CacheReset;              // 2003
    public static readonly EventId PolicyNotFound;          // 2004
    public static readonly EventId PolicyError;             // 2005
    public static readonly EventId TokenIssued;             // 2101
    public static readonly EventId TokenValidationFailed;   // 2102
    public static readonly EventId RefreshTokenReplay;      // 2103
    public static readonly EventId DevSigningKeyGenerated;  // 2104
    public static readonly EventId LoginSucceeded;          // 2201
    public static readonly EventId LoginFailed;             // 2202
    public static readonly EventId AccountLockedOut;        // 2203
    public static readonly EventId EndpointsScanned;        // 2301
    public static readonly EventId RequestDenied;           // 2302
}
```

---

# Cyaim.Authentication

ASP.NET Core 集成：中间件、Minimal API 标注、`HttpContext` 扩展、原生 `[Authorize]` 桥接。

## AddCyaimAuthentication / CyaimAuthAspNetBuilder

`Microsoft.Extensions.DependencyInjection` · 注册核心引擎 + ASP.NET Core 集成，返回链式构建器。

```csharp
public static CyaimAuthAspNetBuilder AddCyaimAuthentication(
    this IServiceCollection services, Action<CyaimAuthOptions>? configure = null);

public sealed class CyaimAuthAspNetBuilder
{
    public IServiceCollection    Services { get; }
    public CyaimAuthCoreBuilder  Core     { get; }
    public CyaimAuthAspNetBuilder AddInMemoryStore();
    public CyaimAuthAspNetBuilder AddJsonFileStore(string filePath);
    public CyaimAuthAspNetBuilder MapStore<TStore>()
        where TStore : class, IUserStore, IRoleStore, IClientStore,
                       IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion;
    public CyaimAuthAspNetBuilder AddPolicy(string name, Func<AuthorizationContext, bool> evaluate);
    public CyaimAuthAspNetBuilder AddPolicy(string name, Func<AuthorizationContext, CancellationToken, Task<bool>> evaluate);
    public CyaimAuthAspNetBuilder AddPolicy<TPolicy>() where TPolicy : class, IAuthPolicy;
}
```

`AddCyaimAuthentication` 内部调用 `AddCyaimAuthCore()`，并将 `CyaimAuthOptions` 的核心字段镜像同步到 `CyaimAuthCoreOptions`（一处配置全部生效），同时注册端点权限扫描与 `[Authorize(Policy = "cyaim:<code>")]` 桥接。

## UseCyaimAuthentication

`Microsoft.AspNetCore.Builder` · 启用权限中间件（须位于 `UseRouting` 之后；`WebApplication` 最简主机直接调用即可）。

```csharp
public static IApplicationBuilder UseCyaimAuthentication(this IApplicationBuilder app);
```

## CyaimAuthOptions

`Cyaim.Authentication.AspNetCore` · ASP.NET Core 集成配置，继承 `CyaimAuthCoreOptions`（含其全部字段）。

```csharp
public class CyaimAuthOptions : CyaimAuthCoreOptions
{
    public string AuthorizationHeaderName { get; set; } = "Authorization";
    public bool   AllowTokenFromQuery { get; set; } = true;
    public string QueryTokenParameter { get; set; } = "access_token";
    public bool   AllowTokenFromCookie { get; set; }          // 默认 false
    public string CookieTokenName { get; set; } = "cyaim_token";
    public bool   ProtectAllEndpoints { get; set; }           // 默认 false
    public bool   AuditDenials { get; set; } = true;
    public bool   ScanEndpointPermissions { get; set; } = true;
    public Func<HttpContext, AuthorizationDecision?, Task>? OnDenied { get; set; }
}
```

## Minimal API 标注扩展

`Microsoft.AspNetCore.Builder`（`CyaimAuthEndpointConventionExtensions`）· 端点链式标注权限。

```csharp
public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, params string[] permissionCodes)
    where TBuilder : IEndpointConventionBuilder;             // 任一满足；无参 = 仅要求已认证
public static TBuilder RequireAllPermissions<TBuilder>(this TBuilder builder, params string[] permissionCodes)
    where TBuilder : IEndpointConventionBuilder;             // 全部满足
public static TBuilder RequireAuthPolicy<TBuilder>(this TBuilder builder, string policyName)
    where TBuilder : IEndpointConventionBuilder;             // 命名 ABAC 策略
public static TBuilder AllowGuest<TBuilder>(this TBuilder builder)
    where TBuilder : IEndpointConventionBuilder;             // 允许游客
```

```csharp
app.MapGet("/users", () => ...).RequirePermission("sys.user.read");
app.MapDelete("/users/{id}", (string id) => ...).RequireAllPermissions("sys.user.write", "sys.user.delete");
app.MapGet("/reports", () => ...).RequireAuthPolicy("working-hours");
app.MapGet("/public", () => "hi").AllowGuest();
```

MVC/控制器场景改用特性 `[RequirePermission(...)]` / `[AllowGuest]`（见 Abstractions），或原生 `[Authorize(Policy = "cyaim:<code>")]` 桥接。用法见 [保护 ASP.NET Core API](../guides/protect-aspnetcore.md)。

## HttpContext 扩展

`Microsoft.AspNetCore.Http`（`CyaimAuthHttpContextExtensions`）· 请求内读取主体与命令式权限检查。

```csharp
public static AuthSubject GetAuthSubject(this HttpContext context);         // 未认证返回游客
public static TokenState  GetTokenState(this HttpContext context);
public static Task<AuthorizationDecision> CheckPermissionAsync(this HttpContext context, string permissionCode);
public static Task<bool>  HasPermissionAsync(this HttpContext context, string permissionCode);
```

WebSocket 消息循环内的细粒度判断常用这些扩展，见 [WebSocket 鉴权](../guides/websocket.md)。

## ICyaimAuthFeature / TokenState

`Cyaim.Authentication.AspNetCore` · 请求级鉴权特征（中间件解析后写入 `HttpContext.Features`）。

```csharp
public interface ICyaimAuthFeature
{
    AuthSubject Subject    { get; }                      // 未认证时为游客
    TokenState  TokenState { get; }
}

public enum TokenState { None = 0, Valid = 1, Invalid = 2 }
```

---

# Cyaim.Authentication.Server

独立 OAuth2/OIDC 授权中心与 SSO。端点清单与协议细节见 [服务器端点参考](server-endpoints.md)。

## AddCyaimAuthServer

`Microsoft.Extensions.DependencyInjection` · 注册授权服务器所需服务（SSO 会话等）。须先调用 `AddCyaimAuthentication()`，本方法不重复注册核心引擎/存储。

```csharp
public static IServiceCollection AddCyaimAuthServer(
    this IServiceCollection services, Action<CyaimAuthServerOptions>? configure = null);
```

## MapCyaimAuthServer

`Microsoft.AspNetCore.Builder` · 映射授权服务器全部端点（发现文档、JWKS、令牌、授权、登录/登出/结束会话、自省、吊销、用户信息）。须在 `app.UseCyaimAuthentication()` 之后调用。

```csharp
public static IEndpointRouteBuilder MapCyaimAuthServer(this IEndpointRouteBuilder endpoints);
```

映射的路由（路径取自 `AuthConstants.Endpoints`）：

```http
GET       /.well-known/openid-configuration
GET       /.well-known/jwks
POST      /connect/token
GET       /connect/authorize
GET|POST  /account/login
GET|POST  /account/logout
GET|POST  /connect/endsession
POST      /connect/introspect
POST      /connect/revocation
GET|POST  /connect/userinfo         # 唯一要求已认证的端点
```

## CyaimAuthServerOptions

`Cyaim.Authentication.Server` · 授权服务器配置。

```csharp
public class CyaimAuthServerOptions
{
    public string? PublicOrigin { get; set; }            // 空则按请求 scheme://host
    public bool EnablePasswordGrant     { get; set; } = true;
    public bool EnableClientCredentials { get; set; } = true;
    public bool EnableAuthorizationCode { get; set; } = true;
    public bool EnableRefreshTokens     { get; set; } = true;
    public string   SsoCookieName      { get; set; } = "cyaim_sso";
    public TimeSpan SsoSessionLifetime { get; set; } = TimeSpan.FromHours(8);
    public string   LoginPath  { get; set; } = AuthConstants.Endpoints.Login;   // "/account/login"
    public string   ServerName { get; set; } = "Cyaim Auth";
    public CookieSecurePolicy SsoCookieSecurePolicy { get; set; } = CookieSecurePolicy.SameAsRequest;
}
```

## SsoSessionService

`Cyaim.Authentication.Server.Sso` · SSO 会话 Cookie 的签发、校验、清除。

```csharp
public sealed class SsoSessionService
{
    public string       Issue(HttpContext context, AuthUser user);   // 返回 sid
    public SsoSession?  Validate(HttpContext context);               // 无效返回 null
    public void         Clear(HttpContext context);
}

public sealed class SsoSession
{
    public string  Sid       { get; set; }
    public string  SubjectId { get; set; }
    public string? Name      { get; set; }
    public DateTimeOffset AuthTime { get; set; }
}
```

搭建授权中心与统一登录见 [搭建授权中心与统一登录](../guides/auth-server-sso.md)。

---

# Cyaim.Authentication.AdminPanel

内嵌 SPA + 管理 REST API。REST 端点、权限映射与请求/响应体见 [管理 API 参考](admin-api.md)。

## AddCyaimAuthAdminPanel

`Microsoft.Extensions.DependencyInjection` · 注册管理面板（需已调用 `AddCyaimAuthentication` 并配置存储）。

```csharp
public static IServiceCollection AddCyaimAuthAdminPanel(
    this IServiceCollection services, Action<CyaimAuthAdminOptions>? configure = null);
```

## MapCyaimAuthAdmin

`Microsoft.AspNetCore.Builder` · 挂载 SPA + 管理 API 到 `BasePath`，返回 `RouteGroupBuilder`。须与 `UseCyaimAuthentication` 中间件配合执行鉴权。

```csharp
public static RouteGroupBuilder MapCyaimAuthAdmin(this IEndpointRouteBuilder endpoints);
```

## CyaimAuthAdminOptions

`Cyaim.Authentication.AdminPanel` · 管理面板配置。

```csharp
public class CyaimAuthAdminOptions
{
    public string  BasePath      { get; set; } = AuthConstants.Endpoints.AdminPanel; // "/auth-admin"
    public string  TokenEndpoint { get; set; } = AuthConstants.Endpoints.Token;      // "/connect/token"
    public string  ClientId      { get; set; } = "cyaim-admin-panel";
    public string? ServerName    { get; set; }
}
```

管理 REST API 前缀为 `{BasePath}/api`。使用见 [使用权限管理面板](../guides/admin-panel.md)。

---

# Cyaim.Authentication.Client

桌面/WASM/控制台/服务间调用的客户端 SDK。

## CyaimAuthClient

`Cyaim.Authentication.Client` · 登录、令牌管理、权限缓存、UserInfo 的一站式客户端。

```csharp
public class CyaimAuthClient : IDisposable
{
    public CyaimAuthClient(CyaimAuthClientOptions options,
        HttpClient? httpClient = null, ITokenCache? cache = null, IAuthClock? clock = null);

    // 状态
    public TokenSet?             CurrentToken       { get; }   // 未登录为 null
    public bool                  IsLoggedIn         { get; }
    public IReadOnlyList<string>? GrantedPermissions { get; }

    // 事件
    public event EventHandler? TokenChanged;
    public event EventHandler? SessionExpired;

    // 发现与登录
    public Task<DiscoveryDocument> DiscoverAsync(CancellationToken ct = default);
    public Task LoginWithPasswordAsync(string userName, string password, CancellationToken ct = default);
    public Task LoginWithClientCredentialsAsync(CancellationToken ct = default);
    public Task ExchangeAuthorizationCodeAsync(string code, string redirectUri, string codeVerifier, CancellationToken ct = default);

    // 令牌
    public Task<bool>   RefreshAsync(CancellationToken ct = default);
    public Task<string> GetAccessTokenAsync(CancellationToken ct = default);  // 必要时自动刷新
    public Task         LogoutAsync(CancellationToken ct = default);

    // 用户信息与权限
    public Task<UserInfoResponse> GetUserInfoAsync(CancellationToken ct = default);
    public Task LoadPermissionsAsync(CancellationToken ct = default);         // 从 UserInfo 拉取
    public bool LoadPermissionsFromToken();                                   // 从访问令牌 perm 声明解析
    public bool HasPermission(string code);                                   // 本地权限门控

    public void Dispose();
}
```

> `HasPermission(code)` 依据本地已加载的授权集（`LoadPermissionsAsync` 或 `LoadPermissionsFromToken` 填充）做 UI 门控，最终鉴权仍由资源服务端执行。桌面/WASM 完整流程见 [桌面/WASM/控制台客户端](../guides/desktop-wasm-clients.md)。

## CyaimAuthClientOptions

`Cyaim.Authentication.Client` · 客户端 SDK 配置。

```csharp
public class CyaimAuthClientOptions
{
    public string  Authority    { get; set; } = string.Empty;   // 必填
    public string  ClientId     { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }                   // 公共客户端为 null
    public List<string> Scopes  { get; set; } = new() { "permissions", "offline_access" };
    public bool     AutoRefresh { get; set; } = true;
    public TimeSpan RefreshSkew { get; set; } = TimeSpan.FromSeconds(60);
    public string   DiscoveryPath { get; set; } = "/.well-known/openid-configuration";
}
```

## ITokenCache 及实现

`Cyaim.Authentication.Client` · 令牌持久化契约（须线程安全），实现「重启免登录」。

```csharp
public interface ITokenCache
{
    TokenSet? Load();                                    // 无/损坏返回 null
    void      Save(TokenSet? tokenSet);                  // 传 null = 清除（登出）
}

// 进程内内存缓存
public class InMemoryTokenCache : ITokenCache
{
    public TokenSet? Load();
    public void      Save(TokenSet? tokenSet);
}

// 文件缓存，写入原子（临时文件 + 替换），可注入平台加密钩子（如 Windows DPAPI）
public class FileTokenCache : ITokenCache
{
    public FileTokenCache(string path,
        Func<byte[], byte[]>? protect = null, Func<byte[], byte[]>? unprotect = null);
    public TokenSet? Load();
    public void      Save(TokenSet? tokenSet);
}
```

```csharp
// Windows 桌面：DPAPI 加密令牌缓存
var cache = new FileTokenCache(
    Path.Combine(appDataDir, "tokens.bin"),
    data => ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser),
    data => ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser));
```

## TokenSet

`Cyaim.Authentication.Client` · 本地持有的一组令牌。

```csharp
public class TokenSet
{
    [JsonPropertyName("access_token")]  public string   AccessToken  { get; set; } = string.Empty;
    [JsonPropertyName("refresh_token")] public string?  RefreshToken { get; set; }
    [JsonPropertyName("expires_at")]    public DateTimeOffset ExpiresAt { get; set; }
    [JsonPropertyName("scopes")]        public string[]? Scopes      { get; set; }
}
```

## Pkce

`Cyaim.Authentication.Client` · 授权码 + PKCE（RFC 7636）工具（静态）。

```csharp
public static class Pkce
{
    public static string CreateCodeVerifier(int length = 64);        // 43-128，越界抛异常
    public static string CreateCodeChallenge(string codeVerifier);   // Base64Url(SHA256(v))，method=S256

    public static string BuildAuthorizeUrl(string authority, string clientId, string redirectUri,
        IEnumerable<string> scopes, string? state, string codeChallenge,
        IDictionary<string, string>? extraParams = null);

    public static string BuildAuthorizeUrl(DiscoveryDocument discovery, string clientId, string redirectUri,
        IEnumerable<string> scopes, string? state, string codeChallenge,
        IDictionary<string, string>? extraParams = null);
}
```

```csharp
string verifier  = Pkce.CreateCodeVerifier();
string challenge = Pkce.CreateCodeChallenge(verifier);
string url = Pkce.BuildAuthorizeUrl("https://auth.example.com", "wasm-client",
    "https://app.example.com/callback", new[] { "openid", "permissions", "offline_access" },
    state: "xyz", codeChallenge: challenge);
// 浏览器登录回调后：
await client.ExchangeAuthorizationCodeAsync(code, "https://app.example.com/callback", verifier);
```

## CyaimAuthHttpMessageHandler

`Cyaim.Authentication.Client` · `DelegatingHandler`：请求前自动附加 `Authorization: Bearer`，响应 401 且可刷新时刷新并重试一次。

```csharp
public class CyaimAuthHttpMessageHandler : DelegatingHandler
{
    public CyaimAuthHttpMessageHandler(CyaimAuthClient client);
    public CyaimAuthHttpMessageHandler(CyaimAuthClient client, HttpMessageHandler innerHandler);
}
```

```csharp
var api = new HttpClient(new CyaimAuthHttpMessageHandler(authClient)
{
    InnerHandler = new HttpClientHandler(),
});
var resp = await api.GetAsync("https://api.example.com/orders"); // 自动带令牌
```

## CyaimAuthException

`Cyaim.Authentication.Client` · 授权服务器返回的 OAuth 2.0 协议错误。

```csharp
public class CyaimAuthException : Exception
{
    public CyaimAuthException(string error, string? errorDescription = null);
    public string  Error            { get; }             // 如 invalid_grant / invalid_client
    public string? ErrorDescription { get; }
}
```

## 协议 DTO

`Cyaim.Authentication.Client` · 与授权服务器交互的响应模型（`System.Text.Json` 特性映射）。

```csharp
public class DiscoveryDocument     // /.well-known/openid-configuration
{
    public string? Issuer, TokenEndpoint, AuthorizationEndpoint, UserInfoEndpoint,
                   RevocationEndpoint, IntrospectionEndpoint, JwksUri, EndSessionEndpoint { get; set; }
}

public class TokenResponse         // RFC 6749 §5.1
{
    public string? AccessToken, TokenType, RefreshToken, Scope { get; set; }
    public long    ExpiresIn { get; set; }
}

public class TokenErrorResponse    // RFC 6749 §5.2
{
    public string? Error, ErrorDescription { get; set; }
}

public class UserInfoResponse      // OIDC UserInfo；role/permissions 兼容单值与数组
{
    public string?   Sub, Name, PreferredUsername, Email, Scope { get; set; }
    public string[]? Role, Permissions { get; set; }
}
```

> 上表为紧凑写法，实际每个属性各自独立声明并带 `[JsonPropertyName]`（如 `access_token`、`preferred_username`）。

---

## 相关文档

- [架构总览](../concepts/architecture.md) —— 六个包如何协作
- [权限模型](../concepts/permission-model.md) —— RBAC 层级 + ABAC + 拒绝优先
- [配置参考](configuration.md) —— 五个 options 类逐项默认值
- [权限代码参考](permission-codes.md) —— 代码语法与通配符
- [判断原因与错误码参考](decisions-and-errors.md) —— `AuthorizationReason` 与 HTTP 响应
- [服务器端点参考](server-endpoints.md) —— OAuth2/OIDC 端点协议
- [管理 API 参考](admin-api.md) —— AdminPanel REST 端点
- [自定义存储](../guides/custom-stores.md) —— 实现六存储接口
- [自定义 ABAC 策略](../guides/custom-policies.md) —— 实现 `IAuthPolicy`
- [桌面/WASM/控制台客户端](../guides/desktop-wasm-clients.md) —— Client SDK 完整用法
- [文档中心首页](../README.md)
