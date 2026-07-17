# 生产部署清单

> 上生产前逐项核对：签名密钥、SSO、Cookie、CORS、令牌有效期、登录锁定、审计、中间件顺序、持久化存储、可观测性。面包屑：[文档中心](../README.md) / 指南

Cyaim.Authentication 的默认值偏向「开箱即用、开发友好」。上生产必须收紧若干项，尤其是**签名密钥**与**多实例一致性**。本清单每项都指明对应的配置项与源码位置，可直接对照。

配置项全表见[配置参考](../reference/configuration.md)；本文只讲生产要点与「为什么」。

---

## 1. 签名密钥（最关键）

令牌签名密钥决定谁能伪造令牌。核心配置在 `CyaimAuthCoreOptions`（`src/Cyaim.Authentication.Core/CyaimAuthCoreOptions.cs`），经 `AddCyaimAuthentication(o => ...)` 一处设置。

- **务必显式配置** `HmacSigningKey`（HS256，对称）**或** `RsaKeyFilePath`（RS256，非对称）二者之一。
- ⚠️ **`HmacSigningKey` 与 `RsaKeyFilePath` 都不设时，框架会自动生成并持久化一个 2048 位 RSA 开发密钥**。这只适合本地开发：多实例各自生成不同密钥会导致令牌互相验不过，且密钥随部署漂移。生产**切勿**依赖自动生成。
- `HmacSigningKey` 至少 **32 字节 UTF-8**；用高熵随机值，从 Secret 管理（环境变量、Key Vault、User Secrets）注入，不要写死在代码/appsettings 里提交。
- **多实例共享**：
  - HS256：所有实例配同一个 `HmacSigningKey`。
  - RS256：所有实例指向**同一份** `RsaKeyFilePath`（共享卷/密钥库同步的同一密钥文件），确保私钥一致、`/.well-known/jwks` 暴露的公钥一致。
- 选型：需要资源服务离线用公钥验签（不回授权中心）→ 用 **RS256**（`RsaKeyFilePath`）；单体或所有服务都能安全共享同一密钥 → **HS256** 更简单。

```csharp
builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.Audience = "your-api";
    // 二选一，从 Secret 注入：
    o.HmacSigningKey = builder.Configuration["Auth:HmacSigningKey"];   // HS256
    // o.RsaKeyFilePath = "/etc/cyaim/keys/signing.rsa.json";         // RS256（多实例共享同一文件）
});
```

## 2. SSO 会话与 Cookie 安全（授权中心）

授权服务器配置在 `CyaimAuthServerOptions`（`src/Cyaim.Authentication.Server/CyaimAuthServerOptions.cs`）。

- **`SsoCookieSecurePolicy`**：默认 `CookieSecurePolicy.SameAsRequest`（仅 HTTPS 请求置 Secure）。**反向代理终止 TLS**（Nginx/Ingress 到后端是明文 HTTP）时，后端「看到」的是 HTTP，`SameAsRequest` 会导致 SSO Cookie **不带 Secure** 明文下发。生产设为 `CookieSecurePolicy.Always`：

  ```csharp
  builder.Services.AddCyaimAuthServer(o =>
  {
      o.PublicOrigin = "https://auth.example.com";   // 发现文档中的对外基地址
      o.SsoCookieSecurePolicy = CookieSecurePolicy.Always;
      o.SsoSessionLifetime = TimeSpan.FromHours(8);
  });
  ```

  同时在管道里配 `ForwardedHeaders`（`X-Forwarded-Proto`），让 ASP.NET Core 正确识别原始 scheme。
- **SSO 签名/会话跨实例**：SSO 会话依赖上面的签名密钥；多实例同样要共享密钥文件（见第 1 项）。
- `SsoCookieName` 默认 `cyaim_sso`；如需与其他 Cookie 隔离可自定义。
- 授权服务器签发的会话/CSRF 相关 Cookie 由框架按 `SsoCookieSecurePolicy` 处理，均为 `HttpOnly`。登录端点（`POST /account/login`）已内置 CSRF 保护（校验 `Origin`/`Referer`）。

## 3. 令牌载体来源与 Cookie

`CyaimAuthOptions`（`src/Cyaim.Authentication/AspNetCore/CyaimAuthOptions.cs`）：

- **`AllowTokenFromQuery` 默认 `true`**：允许 `?access_token=xxx`（WebSocket 握手常用，RFC 6750 §2.3）。但令牌进 URL 会被**反代/应用访问日志、浏览器历史、Referer 记录**，是常见泄露面。
  - 若不用 WebSocket 或 WebSocket 有别的传令牌方式 → 设 `AllowTokenFromQuery = false`。
  - 若必须保留 → 确保访问日志不记录查询串（或脱敏 `access_token` 参数），并全程 HTTPS。
- `AllowTokenFromCookie` 默认 `false`。若为浏览器场景改用 Cookie 载体，务必配合 `HttpOnly` + `Secure` + `SameSite` 的会话 Cookie，并防范 CSRF（Cookie 自动携带带来 CSRF 风险，需额外令牌/校验）。
- `AuthorizationHeaderName`（默认 `Authorization`）——标准 Bearer 头是最安全的载体，优先用它。

## 4. CORS（框架不下发，需宿主配置）

框架**自身不下发任何 CORS 响应头**。`ClientApplication.AllowedCorsOrigins`（`src/Cyaim.Authentication.Abstractions/Models/ClientApplication.cs`）**只是声明记录**，供你读取作为白名单来源——真正的 CORS 必须在宿主用 ASP.NET Core 的 `AddCors`/`UseCors` 配置。

浏览器客户端（WASM、SPA）跨源访问授权端点/资源 API 时：

```csharp
builder.Services.AddCors(o => o.AddPolicy("cyaim", p => p
    .WithOrigins("https://app.example.com")   // 可从 IClientStore 读取 AllowedCorsOrigins 动态填充
    .AllowAnyHeader()
    .AllowAnyMethod()));

// UseCors 须在 UseRouting 之后、UseCyaimAuthentication 之前
app.UseRouting();
app.UseCors("cyaim");
app.UseCyaimAuthentication();
```

不要用 `AllowAnyOrigin()` 配合凭据；用精确来源白名单。

## 5. 令牌有效期与刷新轮换

- `DefaultAccessTokenLifetime` 默认 1 小时、`DefaultRefreshTokenLifetime` 默认 14 天（`ClientApplication` 可按客户端覆盖 `AccessTokenLifetimeSeconds` 等）。访问令牌短、刷新令牌长是标准取舍：访问令牌越短，泄露后的窗口越小。
- **刷新令牌轮换默认开启**：每次刷新签发新令牌并把旧的标记消费；重放已消费令牌会**吊销整个令牌家族**（见 `RefreshTokenRecord` 与 `ITokenStore.ConsumeRefreshTokenAsync`）。用自定义存储时务必保证该消费操作原子——详见[自定义存储](custom-stores.md#3-消费操作的原子性)。
- `ClockSkew` 默认 30 秒，用于容忍多机时钟漂移；确保各实例开启 NTP。
- 需要「登出即失效」或「改密即失效」：这依赖 `AuthUser.SecurityStamp`——改密/收紧授权时更新安全戳，评估器发现令牌里的 `sstamp` 与存储不一致即判定失效（见 `PermissionEvaluator.cs`）。这要求资源服务能读到 `IUserStore`；纯离线验签的下游服务无法即时失效，只能等访问令牌到期。

## 6. 登录失败锁定

暴力破解防护，`CyaimAuthCoreOptions`：

- `MaxAccessFailedCount` 默认 5：连续失败达到阈值即锁定。
- `LockoutDuration` 默认 5 分钟：锁定时长。
- 生产按风险调整（如面向公网的授权中心可缩短阈值、延长锁定，并在反代层加限流/验证码作为补充）。`AuthUser.AccessFailedCount` / `LockoutEnd` 记录状态，`IsLockedOut(now)` 参与鉴权拒绝。

## 7. 审计落盘

- `AuditDenials` 默认 `true`：权限拒绝写审计事件（`CyaimAuthMiddleware.DenyAsync`）。
- `AuditCapacity` 默认 5000：内存环形缓冲条数。
- **`AuditFilePath` 默认 `null`（不落盘）**。生产设为 JSONL 文件路径以持久化审计：

  ```csharp
  builder.Services.AddCyaimAuthentication(o =>
  {
      o.AuditFilePath = "/var/log/cyaim/audit.jsonl";
  });
  ```

  多实例各写各的文件（按实例区分路径），或接自己的日志管道集中收集。审计事件含主体、资源、动作、结果、原因、来源 IP。

## 8. 中间件顺序

- `UseCyaimAuthentication()` **必须在 `UseRouting()` 之后**——它按端点元数据判断权限，需要路由已匹配到端点（见 `CyaimAuthMiddleware` 类注释与 `CyaimAuthApplicationBuilderExtensions.cs`）。`WebApplication` 最简主机（自动路由）下直接调用即可。
- 授权端点/管理面板映射在其后：`app.MapCyaimAuthServer()` / `app.MapCyaimAuthAdmin()`。
- 与其他中间件的相对位置：`UseCors` 在 `UseCyaimAuthentication` 之前；若同时用 ASP.NET Core 原生 `UseAuthentication`/`UseAuthorization`，注意本框架有自己的中间件与 `[Authorize(Policy="cyaim:<code>")]` 桥接，避免重复保护同一端点造成困惑。

推荐顺序：

```csharp
app.UseForwardedHeaders();   // 反代场景：识别原始 scheme/IP
app.UseRouting();
app.UseCors("cyaim");
app.UseCyaimAuthentication();
app.MapCyaimAuthServer();     // 若为授权中心
app.MapCyaimAuthAdmin();      // 若启用管理面板
```

## 9. 用持久化存储替换内存存储

- `AddInMemoryStore()` 的数据**进程重启即丢**，且多实例各存各的、互不同步——**仅用于开发/测试/单机小型部署**。
- 生产用 `AddJsonFileStore(path)`（单机、小规模、可接受文件锁）或自实现的数据库存储 `MapStore<T>()`（推荐，见[自定义存储](custom-stores.md)）。
- **多实例缓存一致性**：`IAuthStoreVersion.Bump()` 是**进程内**信号——A 实例改数据只让 A 的权限缓存失效，B 实例靠 `PermissionCacheTtl`（默认 5 分钟）兜底刷新。要求「改权限立即全局生效」时，在存储的 `Bump()` 里额外广播（如 Redis pub/sub）并让各实例收到后清缓存。
- `MaxCachedPermissionSets` 默认 10000：主体数超限即整体清空重建；大规模用户量按内存预算调整。

## 10. 可观测性

- **指标**：`System.Diagnostics.Metrics`，Meter 名称 **`Cyaim.Authentication`**（`src/Cyaim.Authentication.Core/Engine/AuthMetrics.cs`）。接 OpenTelemetry 或 `dotnet-counters`：

  ```csharp
  builder.Services.AddOpenTelemetry().WithMetrics(m => m.AddMeter("Cyaim.Authentication"));
  ```

  暴露的仪表包括 `cyaim_auth.permission_checks`、`cyaim_auth.permission_denials`、`cyaim_auth.permission_set_cache_hits` / `..._misses`、`cyaim_auth.check_duration`（直方图，ms）、`cyaim_auth.tokens_issued`（带 `kind` 标签）。据此监控拒绝率、缓存命中率、判断耗时。
- **日志**：框架用 `ILogger` 输出结构化事件，带稳定 `EventId`（`AuthLogEvents`）——如权限拒绝、请求拒绝、策略未找到/异常、权限集缓存重建。生产按 `EventId` 建告警（如短时大量 `RequestDenied` 可能是攻击或配置错误）。
- 定期调用 `ITokenStore.CleanupExpiredAsync(now)` 清理过期刷新令牌/授权码（可用后台服务定时触发），避免令牌表无限增长。

---

## 快速核对表

| 项 | 生产要求 |
|---|---|
| 签名密钥 | 显式配 `HmacSigningKey` 或 `RsaKeyFilePath`，多实例共享，从 Secret 注入，勿用自动生成 |
| SSO Cookie | 反代 TLS 终止时 `SsoCookieSecurePolicy = Always` + `ForwardedHeaders` |
| 查询串令牌 | 不需要则 `AllowTokenFromQuery = false`；需要则脱敏访问日志 |
| CORS | 宿主 `UseCors` 精确白名单，框架不下发 |
| 令牌有效期 | 短访问令牌 + 轮换刷新令牌；NTP 校时 |
| 登录锁定 | 按风险调 `MaxAccessFailedCount` / `LockoutDuration` |
| 审计 | 设 `AuditFilePath` 落盘 |
| 中间件顺序 | `UseCyaimAuthentication` 在 `UseRouting` 之后、`UseCors` 之后 |
| 存储 | 用持久化/数据库存储替换 `AddInMemoryStore`；处理跨实例缓存失效 |
| 可观测性 | 采集 Meter `Cyaim.Authentication` + 按 `EventId` 告警 + 定时 `CleanupExpiredAsync` |

---

## 相关文档

- [配置项参考](../reference/configuration.md) — 全部选项与默认值
- [自定义存储](custom-stores.md) — 持久化存储、多实例缓存失效、消费原子性
- [搭建授权中心与统一登录](auth-server-sso.md) — SSO 与反代部署
- [令牌与会话](../concepts/tokens-and-sessions.md) — 刷新轮换、安全戳失效
- [保护 ASP.NET Core API](protect-aspnetcore.md) — 中间件与端点保护
