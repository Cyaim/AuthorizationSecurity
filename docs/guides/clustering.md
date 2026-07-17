# 集群部署（多实例）

> 如何把 Cyaim.Authentication 部署为多实例集群：共享数据、共享密钥、跨实例缓存失效。面包屑：[文档中心](../README.md) / 指南

单实例默认配置（内存/JSON 存储、自动生成密钥、每实例本地缓存）**不能**直接横向扩展。本文说明集群化需要处理的四件事，以及框架为此提供的扩展点——其中三件靠已有抽象即可，一件（跨实例缓存失效）由框架的集群版本组件解决。

## 集群化需要处理什么

| 关注点 | 单实例现状 | 集群方案 |
|---|---|---|
| **授权数据**（用户/角色/权限/客户端） | `InMemoryAuthStore` / `JsonFileAuthStore`，每实例各一份 | 实现存储接口对接共享数据库，见[自定义存储](custom-stores.md) |
| **令牌数据**（刷新令牌/授权码） | 同上，每实例各一份 | **必须**共享：刷新令牌轮换、重放检测、授权码一次性都依赖全局唯一状态 |
| **签名密钥**（JWT / SSO） | 未配置时每实例自动生成 | **必须**共享：所有实例用同一密钥，令牌与 SSO Cookie 才能跨实例互认 |
| **权限集缓存失效** | 每实例本地缓存 + 本地版本号 + TTL 兜底 | 用集群版本让任一实例的授权变更传播到全集群，见下文 |
| **审计** | 内存环形缓冲 + 可选本地文件 | 实现 `IAuditLogger` 落中心化存储（数据库/日志系统） |
| **SSO 会话** | 无状态签名 Cookie | 密钥共享后天然跨实例，无需额外处理 ✓ |
| **端点权限扫描** | 每实例启动时幂等 upsert 到权限定义存储 | 幂等，多实例安全 ✓ |

要点：**大部分能力已由现有抽象覆盖**——存储接口本就为对接数据库设计，签名密钥本就可配置共享。真正需要框架专门支持的只有"跨实例缓存失效"。

## 1. 共享签名密钥

所有实例必须用同一签名密钥。二选一：

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.Audience = "my-api";
    // 方式一：共享 HMAC 密钥（从配置/密钥管理注入，至少 32 字节）
    o.HmacSigningKey = builder.Configuration["Auth:SigningKey"];
    // 方式二：共享 RSA 密钥文件（所有实例挂载同一路径/内容）
    // o.RsaKeyFilePath = "/etc/cyaim/signing-key.json";
});
```

> ⚠️ 切勿在集群中使用未配置密钥时**自动生成**的开发密钥——各实例会各生成一份，令牌互不认。授权服务器还需共享 SSO Cookie 密钥：SSO 密钥由 `HmacSigningKey` 派生，配置了它即自动共享；未配置 `HmacSigningKey` 时授权服务器会把 SSO 密钥写到 `RsaKeyFilePath` 同目录的 `cyaim-sso-key.bin`，多实例需共享该文件。生产建议直接配置 `HmacSigningKey`。

反向代理终止 TLS 时，设 `CyaimAuthServerOptions.SsoCookieSecurePolicy = CookieSecurePolicy.Always`，见[生产部署清单](production-checklist.md)。

## 2. 共享数据与令牌存储

集群的数据与令牌必须放在共享数据库。令牌存储尤其**必须**共享——否则刷新令牌在实例 A 轮换、实例 B 无从得知，重放检测与一次性授权码都会失效。有三条路：

### 2a. 开箱即用：EF Core 共享数据库存储（推荐）

`Cyaim.Authentication.EntityFrameworkCore` 包一次性实现了全部存储接口 + 数据库集群版本，**只需一个共享数据库、无需 Redis**：

```xml
<PackageReference Include="Cyaim.Authentication.EntityFrameworkCore" Version="2.0.0" />
```

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.HmacSigningKey = builder.Configuration["Auth:SigningKey"]; // 所有实例共享
})
.Core
.AddCyaimAuthEntityFrameworkStores(
    db => db.UseNpgsql(builder.Configuration.GetConnectionString("Auth")), // 或 UseSqlServer / UseSqlite
    cluster => cluster.RefreshInterval = TimeSpan.FromSeconds(5));

// 生产用 EF 迁移；演示可用（已容忍并发竞态）：
await app.Services.EnsureCyaimAuthDatabaseCreatedAsync();
```

它做了三件事：`AddDbContextFactory<CyaimAuthDbContext>`（存储以单例运行、每操作创建短生命周期上下文，供单例评估器安全使用）、把 `EntityFrameworkAuthStore` 映射为五个数据接口、以数据库单行计数器 `EfClusterVersionStore` 作为集群版本启用跨实例失效。可运行示例见 [samples/Sample.Cluster](../../samples/Sample.Cluster)。

支持任意 EF Core 关系型提供程序，切换数据库只改 `db.UseXxx(...)`。列表/字典属性以 JSON 列存储；令牌一次性消费用条件 `UPDATE ... WHERE ConsumedAt IS NULL` 的受影响行数实现数据库级原子性。

### 2b. 不用 EF：SqlSugar / Dapper / ADO.NET 手写存储

存储接口不绑定 EF——你完全可以用 SqlSugar、Dapper 或原生 ADO.NET 实现。逐接口方法与实现要点见[自定义存储](custom-stores.md)。集群下有**两个操作必须做对**，下面给出与库无关的原生 SQL 蓝图：

**① 刷新令牌的原子一次性消费**（`ITokenStore.ConsumeRefreshTokenAsync`）——集群防重放的核心。关键是"检查-并-消费"必须在**一条条件 UPDATE**里完成，靠受影响行数判定谁消费成功：

```sql
-- 仅当仍活跃时置为已消费；并发多实例只有一个 UPDATE 影响到 1 行
UPDATE CyaimAuthRefreshTokens
   SET ConsumedAt = @now
 WHERE TokenHash = @hash AND ConsumedAt IS NULL AND RevokedAt IS NULL;
-- 受影响行数 = 1 → 本次消费成功（Consumed）
-- 受影响行数 = 0 → 读该行判定 NotFound / AlreadyConsumed(重放) / Revoked / Expired
```

```csharp
// SqlSugar 示意
int affected = db.Updateable<RefreshTokenRow>()
    .SetColumns(x => x.ConsumedAt == now)
    .Where(x => x.TokenHash == hash && x.ConsumedAt == null && x.RevokedAt == null)
    .ExecuteCommand();
if (affected == 1) return new RefreshTokenConsumeResult(RefreshTokenConsumeStatus.Consumed, record);
// 否则读记录判定具体状态（已消费即视为重放，管理器会吊销整个家族）
```

授权码的 `ConsumeAuthorizationCodeAsync` 同理：`UPDATE ... SET ConsumedAt=@now WHERE CodeHash=@hash AND ConsumedAt IS NULL`，受影响 1 行才算兑换成功。

**② 集群版本的原子递增**（实现 `IClusterVersionStore`）——把版本落在共享库一行里：

```sql
-- 建一张单行表 CyaimAuthClusterVersion(Id INT PK, Version BIGINT)，初始 (1, 0)
UPDATE CyaimAuthClusterVersion SET Version = Version + 1 WHERE Id = 1;   -- IncrementAsync
SELECT Version FROM CyaimAuthClusterVersion WHERE Id = 1;               -- ReadAsync
```

```csharp
public sealed class SqlSugarClusterVersionStore : IClusterVersionStore
{
    private readonly ISqlSugarClient _db;
    public SqlSugarClusterVersionStore(ISqlSugarClient db) => _db = db;

    public Task<long> ReadAsync(CancellationToken ct = default) =>
        Task.FromResult(_db.Queryable<ClusterVersionRow>().Where(x => x.Id == 1).Select(x => x.Version).First());

    public Task<long> IncrementAsync(CancellationToken ct = default)
    {
        _db.Updateable<ClusterVersionRow>().SetColumns(x => x.Version == x.Version + 1).Where(x => x.Id == 1).ExecuteCommand();
        return ReadAsync(ct);
    }
}
```

然后用下面 2c 的方式注册你的存储与版本。

### 2c. 注册手写存储（EF 之外的通用装配）

用 `MapDataStore<TStore>()` 只映射五个**数据**接口（不含版本），版本交给集群版本组件（下一节）：

```csharp
builder.Services.AddSingleton<MyStore>();                    // 你的 SqlSugar/Dapper/ADO 存储（实现 5 个数据接口）
builder.Services.AddSingleton<SqlSugarClusterVersionStore>();

builder.Services.AddCyaimAuthentication(o => { /* 共享密钥 */ })
    .Core
    .MapDataStore<MyStore>()                                 // 映射 5 个数据接口
    .AddClusterCacheInvalidation<SqlSugarClusterVersionStore>(o => o.RefreshInterval = TimeSpan.FromSeconds(5));
```

> 你的存储在每次影响授权结果的写操作（用户/角色/客户端/权限定义）提交后，应调用注入的 `IAuthStoreVersion.Bump()`——就像内置 `InMemoryAuthStore` 与 `EntityFrameworkAuthStore` 那样——由集群版本广播失效。令牌写操作不必 Bump（令牌不影响权限集缓存）。

## 3. 跨实例缓存失效（框架核心支持）

### 问题

权限评估器把每个主体的有效权限编译为 `CompiledPermissionSet` 缓存在**本进程内存**，用一个"数据版本号"判断缓存是否新鲜（`IAuthStoreVersion.Version`）。单实例下，任何写操作调用 `Bump()` 递增版本，缓存随即失效重建。

集群下的问题：实例 A 改了某角色权限并递增了 **A 自己的**版本号，但实例 B 的版本号没变——B 会继续用陈旧的权限集，最长可陈旧到权限集 TTL（`PermissionCacheTtl`，默认 5 分钟）。

### 解决：集群版本

框架用 `IAuthStoreVersion` 这个已有接口作为失效信号的接缝，提供集群感知实现 `ClusterAuthStoreVersion`：它把一个**本地缓存的版本号**（热路径零开销的 `long` 读取）与集群共享的计数器 `IClusterVersionStore` 保持同步。

- **用 EF 存储**（§2a）：`AddCyaimAuthEntityFrameworkStores` 已内置数据库单行版本存储 `EfClusterVersionStore` 并自动启用，**无需自己实现**。
- **手写存储**（§2b/2c）：实现 `IClusterVersionStore` 的 `ReadAsync` / `IncrementAsync`（数据库单行的 SQL 见 §2b），再 `AddClusterCacheInvalidation<T>()`。

若偏好 Redis 而非数据库承载版本，实现如下即可（其余装配同 §2c）：

```csharp
using Cyaim.Authentication.Abstractions.Stores;

public sealed class RedisClusterVersionStore : IClusterVersionStore   // 需 StackExchange.Redis
{
    private readonly IDatabase _redis;
    private const string Key = "cyaim:auth:version";
    public RedisClusterVersionStore(IConnectionMultiplexer mux) => _redis = mux.GetDatabase();

    public async Task<long> ReadAsync(CancellationToken ct = default)
        => (long?)await _redis.StringGetAsync(Key) ?? 0;
    public async Task<long> IncrementAsync(CancellationToken ct = default)
        => await _redis.StringIncrementAsync(Key);   // Redis INCR 原子递增
}
```

### 传播如何发生

`ClusterAuthStoreVersion` 的工作方式：

- **本实例写数据** → 存储在写操作后调用注入的 `IAuthStoreVersion.Bump()`（就像内置 `InMemoryAuthStore` 那样）→ 本地版本即时自增（本实例立刻失效）+ 后台递增共享计数器。若存储愿意在异步写中等待传播完成，可改调 `ClusterAuthStoreVersion.BumpAsync()`。
- **其他实例写数据** → 后台定时器按 `RefreshInterval` 轮询共享计数器，发现变大即更新本地版本并触发 `Changed`，本实例权限集缓存随之在下次判断时重建。

于是：任一实例的授权变更在 **一个轮询间隔内**传播到全集群；间隔之外仍有权限集 TTL 作为最终一致性兜底。版本单调不回退。

> 若你有推送式失效背板（如 Redis Pub/Sub），可把 `RefreshInterval` 设为 `TimeSpan.Zero` 关闭轮询，改由订阅回调触发（订阅到失效消息时调用一次 `ClusterAuthStoreVersion.RefreshAsync()`），实现近实时传播。

### 一致性权衡

| 方案 | 传播延迟 | 复杂度 |
|---|---|---|
| 仅 TTL（不配集群版本） | ≤ `PermissionCacheTtl`（默认 5 分钟） | 零——共享存储即可，无需 `IClusterVersionStore` |
| 集群版本轮询 | ≤ `RefreshInterval`（默认 5 秒） | 低——实现 `IClusterVersionStore` |
| 集群版本 + Pub/Sub 推送 | 近实时 | 中——额外订阅背板 |

安全相关的即时失效（如口令重置吊销令牌）不依赖权限集缓存：它通过**吊销刷新令牌**（共享令牌存储，立即全集群生效）+ **安全戳**（旧访问令牌下次判断即失效，延迟等于上述传播延迟）实现。因此把令牌存储做成共享的，是集群安全性的关键。

## 4. 中心化审计（可选）

内置审计器把事件存在本进程内存（+ 可选本地文件），集群下各实例只见自己的事件。实现 `IAuditLogger` 落中心化存储即可全局查询：

```csharp
public sealed class DatabaseAuditLogger : IAuditLogger { /* WriteAsync/QueryAsync 落库 */ }
// 注册（覆盖默认审计器）
builder.Services.AddSingleton<IAuditLogger, DatabaseAuditLogger>();
```

## 最省事的路径

用 EF Core 包（§2a）即可一步满足"共享数据 + 共享令牌 + 集群缓存失效"，**只需一个共享数据库**：

```csharp
builder.Services.AddCyaimAuthentication(o => o.HmacSigningKey = 共享密钥)
    .Core
    .AddCyaimAuthEntityFrameworkStores(db => db.UseNpgsql(连接串));
```

可运行的两实例演示：[samples/Sample.Cluster](../../samples/Sample.Cluster)。用 SqlSugar/Dapper/ADO 则按 §2b/§2c 手写，两个原子操作照 §2b 的 SQL 实现即可。

## 集群部署清单

- [ ] 所有实例配置**同一** `HmacSigningKey`（或共享同一 `RsaKeyFilePath` 内容）
- [ ] 数据与令牌存储对接**共享数据库**（EF 包 `AddCyaimAuthEntityFrameworkStores`，或手写存储 + `MapDataStore<T>`）
- [ ] 令牌存储的 `ConsumeRefreshTokenAsync` / `ConsumeAuthorizationCodeAsync` 在共享存储上**原子**（条件 UPDATE 判受影响行数，防并发重放）
- [ ] 启用 `AddClusterCacheInvalidation`（DB 单行 / Redis 版本存储），或接受 TTL 级最终一致
- [ ] 手写存储在授权数据写操作后调用 `IAuthStoreVersion.Bump()`（EF 存储已自动）
- [ ] 反代终止 TLS 时 `SsoCookieSecurePolicy = Always`
- [ ] 生产用 EF 迁移建表，扩容前先迁移一次（勿让每实例并发建表）
- [ ] 审计落中心化存储（如需全局审计）
- [ ] 会话粘性非必需（SSO 是无状态签名 Cookie）

## 相关文档

- [自定义存储（EF/数据库/SqlSugar/Dapper）](custom-stores.md)
- [令牌与会话](../concepts/tokens-and-sessions.md)
- [权限模型（缓存与失效）](../concepts/permission-model.md)
- [生产部署清单](production-checklist.md)
- [示例总览](../samples.md)
