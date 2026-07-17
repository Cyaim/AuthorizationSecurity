# 自定义存储（EF / 数据库）

> 用自己的持久化后端替换内置内存/JSON 存储：实现六个存储接口（或其子集），经 `MapStore<T>` 以单例注册。面包屑：[文档中心](../README.md) / 指南

Cyaim.Authentication 把「数据从哪来」与「怎么鉴权」彻底解耦。核心引擎（评估器、令牌服务、授权服务器、管理面板）只依赖 `Cyaim.Authentication.Abstractions.Stores` 命名空间下的六个接口，不关心背后是内存、JSON 文件还是 SQL Server / PostgreSQL / MongoDB。要接入自己的数据库，只需实现这些接口并注册即可。

> **不想手写？** `Cyaim.Authentication.EntityFrameworkCore` 包已用 EF Core 实现了全部接口 + 集群版本，`AddCyaimAuthEntityFrameworkStores(db => db.UseNpgsql(...))` 一行接入任意 EF 提供程序，见[集群部署](clustering.md) §2a。
>
> **用 SqlSugar / Dapper / ADO.NET？** 完全支持——接口不绑定 EF。集群下两个必须做对的原子操作（条件消费令牌、递增集群版本）的原生 SQL 蓝图见[集群部署](clustering.md) §2b。

内置实现可作为参照：`InMemoryAuthStore`（`src/Cyaim.Authentication.Core/Stores/InMemoryAuthStore.cs`）一个类实现全部六个接口；`JsonFileAuthStore` 在其基础上加落盘。

---

## 六个存储接口一览

| 接口 | 职责 | 关键约束 |
|---|---|---|
| `IUserStore` | 用户账户 CRUD 与分页 | `UserName` 唯一（不区分大小写） |
| `IRoleStore` | 角色 CRUD、全量读取 | `Name` 唯一（不区分大小写） |
| `IClientStore` | OAuth 客户端应用 CRUD | 按 `ClientId` 主键 |
| `IPermissionDefinitionStore` | 权限清单（管理面板展示/分配用） | 按 `Code` 主键 |
| `ITokenStore` | 刷新令牌与授权码（存哈希） | 消费操作须原子 |
| `IAuthStoreVersion` | 授权数据版本号 | 变更后 `Bump()` 触发缓存失效 |

`MapStore<T>` 要求单个类型同时实现全部六个接口；但你也可以分别用不同类型实现其中一部分（见[只实现部分接口](#只实现部分接口)）。

所有方法签名与命名空间以源码为准，见 `src/Cyaim.Authentication.Abstractions/Stores/*.cs`。

---

## IUserStore

```csharp
public interface IUserStore
{
    Task<AuthUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default);
    Task<AuthUser?> FindByUserNameAsync(string userName, CancellationToken cancellationToken = default);
    Task CreateAsync(AuthUser user, CancellationToken cancellationToken = default);
    Task UpdateAsync(AuthUser user, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
    // search 匹配用户名/显示名/邮箱；skip/take 分页
    Task<IReadOnlyList<AuthUser>> ListAsync(string? search, int skip, int take, CancellationToken cancellationToken = default);
    Task<int> CountAsync(string? search, CancellationToken cancellationToken = default);
}
```

- `FindByUserNameAsync` 必须**不区分大小写**匹配；登录、口令校验都走它。
- `CreateAsync` / `UpdateAsync` 应在 `UserName` 冲突时抛异常（内置实现抛 `InvalidOperationException`）。
- `AuthUser`（`src/Cyaim.Authentication.Abstractions/Models/AuthUser.cs`）含 `PasswordHash`、`SecurityStamp`、`IsEnabled`、`LockoutEnd`、`AccessFailedCount`、`Roles`、`DirectPermissions`、`DeniedPermissions`、`Claims` 等字段——完整持久化，勿丢字段。评估器读取 `IsEnabled`/`IsLockedOut(now)`/`SecurityStamp` 判定令牌是否失效。

## IRoleStore

```csharp
public interface IRoleStore
{
    Task<AuthRole?> FindByIdAsync(string id, CancellationToken cancellationToken = default);
    Task<AuthRole?> FindByNameAsync(string name, CancellationToken cancellationToken = default);
    // 角色数量通常有限；评估器编译权限集时需要全量层级
    Task<IReadOnlyList<AuthRole>> GetAllAsync(CancellationToken cancellationToken = default);
    Task CreateAsync(AuthRole role, CancellationToken cancellationToken = default);
    Task UpdateAsync(AuthRole role, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
}
```

- `GetAllAsync` 是权限评估的热路径入口：评估器缓存整张角色图（按 `PermissionCacheTtl` 与版本号刷新），按 `AuthRole.ParentRoles` 做 BFS 展开继承。返回全量即可，无需自己算继承。
- `AuthRole.IsSystem` 为 `true` 的内置角色，`DeleteAsync` 应拒绝删除。

## IClientStore

```csharp
public interface IClientStore
{
    Task<ClientApplication?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ClientApplication>> GetAllAsync(CancellationToken cancellationToken = default);
    Task CreateAsync(ClientApplication client, CancellationToken cancellationToken = default);
    Task UpdateAsync(ClientApplication client, CancellationToken cancellationToken = default);
    Task DeleteAsync(string clientId, CancellationToken cancellationToken = default);
}
```

- `ClientApplication`（`ClientApplication.cs`）含 `ClientSecretHash`、`AllowedGrantTypes`、`RedirectUris`、`AllowedScopes`、`RequirePkce`、`Permissions`、`AllowedCorsOrigins` 等。授权服务器凭 `FindByClientIdAsync` 校验客户端凭据与回调地址。

## IPermissionDefinitionStore

```csharp
public interface IPermissionDefinitionStore
{
    // 批量登记：存在则更新显示信息，不覆盖手工修改的来源
    Task UpsertAsync(IEnumerable<PermissionDefinition> definitions, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<PermissionDefinition>> GetAllAsync(CancellationToken cancellationToken = default);
    Task DeleteAsync(string code, CancellationToken cancellationToken = default);
}
```

- 启动时端点扫描器（`ScanEndpointPermissions=true`）会把发现的权限代码 `UpsertAsync` 进来，`PermissionDefinition.Origin` 标为 `EndpointDiscovery`。管理面板的权限清单来自 `GetAllAsync`。

## ITokenStore

```csharp
public interface ITokenStore
{
    Task SaveRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default);
    Task<RefreshTokenRecord?> FindRefreshTokenAsync(string tokenHash, CancellationToken cancellationToken = default);
    Task UpdateRefreshTokenAsync(RefreshTokenRecord record, CancellationToken cancellationToken = default);

    // 原子消费：仅当存在、未消费、未吊销、未过期时标记已消费并返回 Consumed，否则返回相应状态而不修改
    Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(string tokenHash, DateTimeOffset now, CancellationToken cancellationToken = default);

    Task RevokeRefreshTokenFamilyAsync(string familyId, CancellationToken cancellationToken = default);
    Task RevokeSubjectRefreshTokensAsync(string subjectId, string? clientId = null, CancellationToken cancellationToken = default);
    Task RevokeClientRefreshTokensAsync(string clientId, CancellationToken cancellationToken = default);

    Task SaveAuthorizationCodeAsync(AuthorizationCodeRecord record, CancellationToken cancellationToken = default);
    // 原子取出并标记消费；不存在/已消费/已过期返回 null
    Task<AuthorizationCodeRecord?> ConsumeAuthorizationCodeAsync(string codeHash, CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}
```

- 存**哈希**，不存明文。`RefreshTokenRecord.TokenHash` / `AuthorizationCodeRecord.CodeHash` 已是 `Base64URL(SHA-256(明文))`，直接存即可。
- `ConsumeRefreshTokenAsync` 的返回值 `RefreshTokenConsumeResult { Status, Record }`，状态枚举 `RefreshTokenConsumeStatus`：`Consumed / NotFound / AlreadyConsumed / Revoked / Expired`。这是刷新令牌轮换与重放检测的核心，**原子性至关重要**（见下）。

## IAuthStoreVersion

```csharp
public interface IAuthStoreVersion
{
    long Version { get; }        // 单调递增
    void Bump();                 // 存储变更后调用
    event Action<long>? Changed; // 版本变更通知
}
```

- 任何影响鉴权结果的写入（用户/角色/权限的增删改）后调用 `Bump()`。评估器缓存的编译权限集带版本号，`Version` 变化即失效重建。
- 令牌读写（刷新令牌、授权码）**不需要** `Bump()`——它们不改变权限结果。内置实现对这类写入只回调内部的 `OnMutated()`（供落盘），不递增版本。

---

## 实现要点

### 1. 唯一性
`IUserStore.UserName`、`IRoleStore.Name` 须保证不区分大小写唯一。数据库层建唯一索引（如 `LOWER(user_name)` 上的唯一约束），并在 `Create`/`Update` 改名时校验冲突后抛异常，避免脏数据。

### 2. 读写隔离（深拷贝）
存储返回的对象**不应与内部状态共享引用**。评估器与调用方可能修改返回的 `AuthUser.Roles` 等集合，若与存储内部同一引用会造成污染。内置内存存储对每次读写都深拷贝（`AuthUser.Clone()` / `AuthRole.Clone()` 手写深拷贝，比 JSON 往返快约一个数量级）。EF/数据库实现天然隔离——每次查询是新实体，但要注意：若开了 EF 变更跟踪并复用同一 `DbContext`，返回的实体仍被跟踪，建议查询用 `AsNoTracking()`。

### 3. 消费操作的原子性
`ConsumeRefreshTokenAsync` 与 `ConsumeAuthorizationCodeAsync` 必须在并发下保证**同一令牌只被成功消费一次**——这是防重放的底线。刷新令牌轮换时旧令牌被标记消费；若已消费的令牌被再次提交，说明发生重放，调用方会吊销整个令牌家族。

- 内存实现：在锁内做 check-then-set。
- 数据库实现：用条件更新一次完成，例如
  ```sql
  UPDATE refresh_tokens
  SET consumed_at = @now
  WHERE token_hash = @hash AND consumed_at IS NULL
    AND revoked_at IS NULL AND expires_at > @now;
  -- 受影响行数 = 1 → Consumed；= 0 → 再查一次判断是 NotFound/AlreadyConsumed/Revoked/Expired
  ```
  切勿「先 SELECT 再 UPDATE」而不加乐观并发控制，否则两个并发刷新可能都读到「未消费」而双双成功。

### 4. 版本号触发缓存失效
写入用户/角色/权限后调用 `Bump()`。`IAuthStoreVersion` 的版本是**进程内**信号：多实例部署时，A 实例改了数据、`Bump()` 只让 A 的缓存失效，B 实例感知不到。此时依赖 `CyaimAuthCoreOptions.PermissionCacheTtl`（默认 5 分钟）作为兜底刷新窗口——见[配置参考](../reference/configuration.md)与[生产清单](production-checklist.md)。若需跨实例即时失效，可在 `Bump()` 里额外广播（如 Redis pub/sub）并在收到通知时清缓存。

---

## 用 MapStore&lt;T&gt; 注册（单例约束）

存储经 `MapStore<T>` 注册，把一个实现类型映射到全部六个接口。**注册为单例**（`src/Cyaim.Authentication.Core/DependencyInjection/CyaimAuthCoreServiceCollectionExtensions.cs`）：

```csharp
builder.Services
    .AddCyaimAuthentication(o =>
    {
        o.Issuer = "https://auth.example.com";
        o.HmacSigningKey = builder.Configuration["Auth:SigningKey"];
    })
    .MapStore<MyDbAuthStore>();   // 你的实现，须实现全部六个接口
```

`MapStore<T>` 的类型约束（编译期强制）：

```csharp
public CyaimAuthCoreBuilder MapStore<TStore>()
    where TStore : class, IUserStore, IRoleStore, IClientStore,
                   IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion;
```

> ⚠️ **单例约束**：`MapStore<T>` 用 `TryAddSingleton` 注册。`TStore` 本身也须能作为单例解析——你要先自行注册它，例如 `services.AddSingleton<MyDbAuthStore>()`。因此**不能让存储直接持有 Scoped 的 `DbContext`**（单例捕获 Scoped 服务会导致「Cannot consume scoped service from singleton」或跨请求复用同一 DbContext 的并发错误）。正确做法是在存储内部用 `IDbContextFactory<T>` 或 `IServiceScopeFactory` **按操作**创建短生命周期作用域。

---

## EF Core 存储骨架（IDbContextFactory）

下面是一个基于 EF Core 的骨架，演示单例存储如何安全地按操作创建 `DbContext`。仅展示部分方法，其余方法照同样模式补齐。

```csharp
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.EntityFrameworkCore;

// 你的 DbContext（映射 AuthUser/AuthRole/... 或你自己的实体后再转换）
public sealed class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }
    public DbSet<AuthUser> Users => Set<AuthUser>();
    public DbSet<AuthRole> Roles => Set<AuthRole>();
    public DbSet<ClientApplication> Clients => Set<ClientApplication>();
    public DbSet<PermissionDefinition> Permissions => Set<PermissionDefinition>();
    public DbSet<RefreshTokenRecord> RefreshTokens => Set<RefreshTokenRecord>();
    public DbSet<AuthorizationCodeRecord> AuthCodes => Set<AuthorizationCodeRecord>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AuthUser>().HasKey(x => x.Id);
        b.Entity<AuthUser>().HasIndex(x => x.UserName).IsUnique();      // 唯一性
        b.Entity<AuthRole>().HasKey(x => x.Id);
        b.Entity<AuthRole>().HasIndex(x => x.Name).IsUnique();
        b.Entity<ClientApplication>().HasKey(x => x.ClientId);
        b.Entity<PermissionDefinition>().HasKey(x => x.Code);
        b.Entity<RefreshTokenRecord>().HasKey(x => x.TokenHash);
        b.Entity<AuthorizationCodeRecord>().HasKey(x => x.CodeHash);
        // 集合字段（Roles/Permissions 等）需配置为 JSON 列或拆表——此处省略
    }
}

// 单例存储：绝不持有 DbContext，只持有工厂；每个操作 using 一个短命 DbContext
public sealed class EfAuthStore :
    IUserStore, IRoleStore, IClientStore, IPermissionDefinitionStore, ITokenStore, IAuthStoreVersion
{
    private readonly IDbContextFactory<AuthDbContext> _factory;
    private long _version;

    public EfAuthStore(IDbContextFactory<AuthDbContext> factory)
    {
        _factory = factory;
        _version = 1;
    }

    // ---- IAuthStoreVersion ----
    public long Version => Interlocked.Read(ref _version);
    public event Action<long>? Changed;
    public void Bump()
    {
        long v = Interlocked.Increment(ref _version);
        Changed?.Invoke(v);
    }

    // ---- IUserStore（示例两个方法）----
    public async Task<AuthUser?> FindByIdAsync(string id, CancellationToken ct = default)
    {
        await using AuthDbContext db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    public async Task CreateAsync(AuthUser user, CancellationToken ct = default)
    {
        await using AuthDbContext db = await _factory.CreateDbContextAsync(ct);
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);   // 唯一索引冲突会在此抛 DbUpdateException
        Bump();                          // 影响鉴权 → 递增版本
    }

    // ---- ITokenStore：原子消费（条件更新）----
    public async Task<RefreshTokenConsumeResult> ConsumeRefreshTokenAsync(
        string tokenHash, DateTimeOffset now, CancellationToken ct = default)
    {
        await using AuthDbContext db = await _factory.CreateDbContextAsync(ct);
        // 单条条件更新，受影响行数=1 即本次成功消费（避免 SELECT-then-UPDATE 竞态）
        int affected = await db.RefreshTokens
            .Where(r => r.TokenHash == tokenHash && r.ConsumedAt == null
                        && r.RevokedAt == null && r.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.ConsumedAt, now), ct);

        RefreshTokenRecord? record = await db.RefreshTokens.AsNoTracking()
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash, ct);

        if (affected == 1)
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Consumed, record);
        if (record == null)
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.NotFound, null);
        if (record.RevokedAt != null)
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Revoked, record);
        if (record.ConsumedAt != null)
            return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.AlreadyConsumed, record);
        return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Expired, record);
    }

    // 其余接口方法（UpdateAsync/DeleteAsync/ListAsync/角色/客户端/权限定义/授权码 等）照此补齐；
    // 影响鉴权结果的写入后调用 Bump()，令牌类写入不需要 Bump()。
    // ...
}
```

注册（注意 `AddPooledDbContextFactory` / `AddDbContextFactory` 是线程安全的工厂，适配单例存储）：

```csharp
builder.Services.AddDbContextFactory<AuthDbContext>(o =>
    o.UseNpgsql(builder.Configuration.GetConnectionString("Auth")));

builder.Services.AddSingleton<EfAuthStore>();   // 存储本体单例

builder.Services
    .AddCyaimAuthentication(o => o.Issuer = "https://auth.example.com")
    .MapStore<EfAuthStore>();                    // 映射到六个接口
```

> `IDbContextFactory<T>` 本身是单例、线程安全，每次 `CreateDbContextAsync()` 返回全新短命上下文，正好匹配「单例存储、按操作用作用域」的约束。用 `IServiceScopeFactory` + `scope.ServiceProvider.GetRequiredService<DbContext>()` 也可，但工厂更直接。

---

## 只实现部分接口

不一定要一个类型实现全部六个。`MapStore<T>` 只是便捷方法——你可以按接口分别 `TryAddSingleton` 注册不同实现。评估器对存储接口都做**可选**处理：未注册 `IUserStore`/`IRoleStore` 时，回退到主体令牌自带的权限声明（分布式资源服务常见）。

例如：授权中心用完整数据库存储，而下游资源服务只需令牌离线鉴权、根本不接数据库——那台资源服务什么存储都不用注册，评估器直接用令牌里的 `perm` 声明。

若要混合（如用户/角色走 EF，令牌走 Redis）：

```csharp
builder.Services.AddSingleton<EfUserRoleStore>();
builder.Services.AddSingleton<RedisTokenStore>();

builder.Services.AddCyaimAuthentication(/* ... */);

// 分别映射（在 AddCyaimAuthentication 之后，覆盖默认无存储状态）
builder.Services.AddSingleton<IUserStore>(sp => sp.GetRequiredService<EfUserRoleStore>());
builder.Services.AddSingleton<IRoleStore>(sp => sp.GetRequiredService<EfUserRoleStore>());
builder.Services.AddSingleton<IAuthStoreVersion>(sp => sp.GetRequiredService<EfUserRoleStore>());
builder.Services.AddSingleton<ITokenStore>(sp => sp.GetRequiredService<RedisTokenStore>());
// 未注册 IClientStore/IPermissionDefinitionStore → 相应功能（客户端凭据、管理面板权限清单）不可用
```

> 注意：核心 DI 用 `TryAddSingleton`，谁先注册谁生效。用 `services.AddSingleton<IUserStore>(...)`（非 Try）可确保覆盖。缺失某接口时，依赖它的功能会退化（如无 `IClientStore` 则授权服务器无法校验客户端），按你的部署形态取舍。

---

## 相关文档

- [配置项参考](../reference/configuration.md) — `PermissionCacheTtl`、`MaxCachedPermissionSets` 等缓存相关配置
- [架构总览](../concepts/architecture.md) — 存储/引擎/宿主的分层
- [令牌与会话](../concepts/tokens-and-sessions.md) — 刷新令牌轮换与重放检测
- [生产部署清单](production-checklist.md) — 多实例缓存失效、持久化存储替换内存存储
- [自定义 ABAC 策略](custom-policies.md) — 另一类扩展点
