# 交付验证报告（Cyaim.Authentication 2.0）

> 本报告汇总 2.0 重构的可交付性证据：构建、测试、基准、端到端协议验证、评审结论。
> 验证环境：Windows 11（10.0.26200）、.NET SDK 9.0.3xx、12 逻辑核。日期：2026-07-16/17。

## 1. 构建

- `dotnet build Cyaim.Authentication.sln`：**0 错误 / 0 警告**（七个 src 包 + 示例 + 测试与基准项目）
- `dotnet pack -c Release`：**7 个 NuGet 包**全部产出（`artifacts/packages/*.2.0.0.nupkg`，含 `Cyaim.Authentication.EntityFrameworkCore`）
- 多目标验证：Abstractions/Client `netstandard2.0;net8.0`，Core `netstandard2.0;net8.0;net9.0`，ASP.NET 集成/Server/AdminPanel/EntityFrameworkCore `net8.0;net9.0`

## 2. 自动化测试

### 2.1 单元测试（tests/Cyaim.Authentication.Tests）

```
已通过! - 失败: 0，通过: 163，已跳过: 0，总计: 163
```

覆盖：权限码规范化与非法输入、通配符匹配（单段/多段/中段/回溯）、拒绝优先、角色层级（继承/菱形/环）、禁用与锁定、游客角色、令牌声明回退、缓存命中/版本失效/TTL 过期、ABAC 策略 fail-closed、PBKDF2（含 RFC 7914 标准向量交叉验证）、JWT 签发校验（HS256/RS256、过期、错误签名/iss/aud）、JWKS、刷新令牌轮换与重放家族吊销、存储 CRUD/唯一性/深拷贝/授权码一次性、JSON 文件持久化往返、登录锁定策略、审计查询，以及第 6 节 7 项安全修复的回归测试（含 32 路并发原子消费、安全戳失效、假哈希计时、落盘异常不崩溃）。

### 2.2 集成测试（tests/Cyaim.Authentication.IntegrationTests，TestServer 内存宿主）

```
已通过! - 失败: 0，通过: 40，已跳过: 0，总计: 40
```

覆盖：中间件鉴权矩阵（401/WWW-Authenticate、invalid_token、403 NoMatchingGrant/DeniedByRule、角色继承、RequireAll、AllowGuest、仅认证、ABAC 策略真/假）、令牌签发形态与 Cache-Control、userinfo 声明还原、禁用用户 invalid_grant + 403、client_credentials 成功/失败、完整授权码+PKCE+SSO 流程、错误 verifier、授权码重放、登出、刷新令牌轮换与重放家族吊销、自省（Basic）、吊销、管理面板 CRUD/权限隔离/审计查询/重生密钥、WebSocket 握手鉴权（有/无令牌/无权限）、Client SDK 端到端（登录/权限/自动刷新/DelegatingHandler），以及 5 项安全修复的端到端回归（口令重置吊销会话、禁用吊销、委派管理员越权拦截、非法权限码 400、重置仅失效旧会话）。

## 3. 性能基准（tests/Cyaim.Authentication.Benchmarks）

完整数据见 [docs/benchmark-results.md](docs/benchmark-results.md)。要点（中位数）：

| 指标 | 1.x（线性扫描） | 2.0（编译权限集） | 提升 |
|---|---:|---:|---:|
| 100 端点/次判断 | 93,354 ns | 22.3 ns | **4,187x** |
| 1,000 端点/次判断 | 882,855 ns | 20.2 ns | **43,609x** |
| 10,000 端点/次判断 | 9,226,486 ns | 25.5 ns | **362,019x** |

端到端评估器（真实 DI + 1,000 权限用户）：缓存命中 **146.7 ns/次**（单线程 681 万次/秒；8 线程 2,986 万次/秒）；万条权限集编译一次性成本约 1.4–2.0 ms。

## 4. 端到端协议验证（真实 Kestrel + curl）

### 4.1 资源服务（Sample.WebApi，13 项）

| # | 场景 | 结果 |
|---|---|---|
| 1 | 游客访问 AllowGuest 端点 | 200 ✅ |
| 2 | 无令牌访问受保护端点 | 401 + `WWW-Authenticate: Bearer` + JSON 错误体 ✅ |
| 3 | bob（order-viewer）读订单 | 200 ✅ |
| 4 | bob 创建订单（无权限） | 403 `NoMatchingGrant` ✅ |
| 5 | alice（order-admin，`demo.order.**`）创建 | 201 ✅ |
| 6 | carol 删除（**拒绝优先**：继承 `demo.order.**` 但显式拒绝 delete） | 403 `DeniedByRule` ✅ |
| 7 | carol 读取（两级角色继承） | 200 ✅ |
| 8 | alice 删除 | 204 ✅ |
| 9 | 游客访问控制器 `[AllowGuest]` 动作 | 200 ✅ |
| 10 | alice 访问未授权控制器 | 403 ✅ |
| 11 | 伪造令牌 | 401 ✅ |
| 12 | 已认证访问 `RequirePermission()` 端点 | 200 ✅ |
| 13 | WebSocket 端点无令牌握手 | 401 ✅ |

审计落盘验证（logs/audit.jsonl 节选）：

```json
{"Category":4,"Outcome":1,"SubjectId":"sys_guest","Resource":"/api/orders","Action":"GET","Detail":"GuestNotAllowed: demo.order.read","RemoteIp":"127.0.0.1"}
{"Category":4,"Outcome":1,"SubjectName":"Carol 受限管理员","Resource":"/api/orders/0","Action":"DELETE","Detail":"DeniedByRule: demo.order.delete","RemoteIp":"127.0.0.1"}
```

### 4.2 授权中心（Sample.AuthServer，27 项）

发现文档、JWKS、密码授权（含错误口令 400 invalid_grant）、client_credentials（含错误密钥 401 invalid_client）、userinfo（200/401）、管理面板 API（stats/users/config）、SPA 服务——12 项全过。

SSO + 授权码 + PKCE 全流程 15 项：

| # | 场景 | 结果 |
|---|---|---|
| 13 | 未登录 authorize → 302 登录页（returnUrl 编码携带） | ✅ |
| 14 | 登录表单 → 302 + SSO Cookie | ✅ |
| 15 | 已登录 authorize → 302 回调携带 code + state 原样透传 | ✅ |
| 16 | **SSO**：第二次 authorize 免登录直发 code | ✅ |
| 17 | 授权码 + code_verifier 兑换 → Bearer AT + RT | ✅ |
| 18 | 授权码重放 | 400 ✅ |
| 19 | 错误 code_verifier（PKCE S256） | 400 ✅ |
| 20 | 未注册 redirect_uri | 400 且不重定向 ✅ |
| 20b | returnUrl 携带 CRLF（响应头注入尝试） | 安全回退 302 → `/` ✅（见 §5 修复记录） |
| 21 | 刷新令牌轮换（新旧不同） | ✅ |
| 22 | 重放已轮换的旧 RT | 400 + 家族吊销 ✅ |
| 23 | 家族内新 RT 同步失效 | 400 ✅ |
| 24 | 自省（Basic 客户端认证）AT → active:true + 声明 | ✅ |
| 25 | RFC 7009 吊销 RT → 自省 active:false | ✅ |
| 26 | 登出清 SSO → authorize 重新要求登录 | ✅ |

结构化日志验证：签发/拒绝/扫描事件均带 EventId（2101/2301/2302/3001+）输出；端点权限扫描自动登记权限定义（资源服务 6 个、授权中心 11 个）。

## 5. 验证过程中发现并修复的问题

| 问题 | 修复 |
|---|---|
| 端点权限扫描在最简主机下拿不到端点数据源（扫描结果恒为 0） | `UseCyaimAuthentication` 时从 `IEndpointRouteBuilder` 捕获数据源 + 扫描延迟到 `ApplicationStarted`（src/Cyaim.Authentication/AspNetCore/EndpointPermissionScanner.cs） |
| 登录 returnUrl 携带 CR/LF 控制字符导致写 Location 头抛异常（500，响应头注入面） | `IsSafeReturnUrl` 拒绝一切控制字符（src/Cyaim.Authentication.Server/Endpoints/ServerHttp.cs） |

## 6. 多智能体对抗评审与修复

对 `src/` 六个包做了四维（安全 / 正确性 / 并发 / 热路径-API）并行评审，每个候选发现由 2 名独立"怀疑者"agent 逐条尝试反驳，仅在代码中确认完整触发链路者保留。15 个候选中 **11 个确认**（去重后 7 个真实缺陷），4 个被反驳驳回（如"自省端点未校验令牌归属"经核实符合 RFC 7662 设计、"401 重试抛 ObjectDisposedException"前提不成立）。7 个真实缺陷已全部修复，并各配回归测试：

| # | 严重度 | 缺陷 | 修复 |
|---|---|---|---|
| 1 | Critical | 口令重置/安全戳轮换不吊销任何已签发令牌，账户被盗后无法踢出 | 重置口令/禁用/删除用户时调用 `RefreshTokenManager.RevokeAllForSubjectAsync` 吊销刷新令牌；`PermissionEvaluator` 比对令牌 `sstamp` 与用户当前 `SecurityStamp`，不一致即判失效；中间件对"仅要求已认证"的端点（如 userinfo、`/api/me`）也经 `IsSubjectActiveAsync` 强制此校验（否则旧令牌在无权限码端点仍可通过——修复时经实测发现并补全） |
| 2 | High | 仅持 `auth.admin.users` 的委派管理员可通过编辑用户自授 `auth.admin.**` 纵向越权 | 设置 Roles 需 `ManageRoles`、设置权限需 `ManagePermissions`，否则 403（恢复职责分离） |
| 3 | Medium | 非法权限码（如 `sys.**.read`）被静默丢弃，导致 deny 规则不生效 | 用户/角色写入时用 `PermissionCode.TryNormalize` 校验，非法即 400 |
| 4 | High | `RefreshTokenManager.ExchangeAsync` 先查后写非原子（TOCTOU），并发下同一令牌可被兑换两次绕过重放检测 | 新增 `ITokenStore.ConsumeRefreshTokenAsync` 原子消费（锁内 check-then-set），管理器改用之；32 路并发测试证明恰好一次成功 |
| 5 | High | `JsonFileAuthStore` 定时器回调中的落盘 IO 异常（ThreadPool 未捕获）会终止进程 | 定时器回调包裹 try/catch，落盘失败记入 `LastSaveError` 并保留待存标记重试，不再崩溃 |
| 6 | Low | 用户名不存在时跳过 PBKDF2，产生可枚举用户名的计时侧信道 | 用户不存在时对固定假哈希执行等价开销的 Verify，抹平时延 |
| 7 | Low | `EndpointPermissionResolver` 以 Endpoint 引用为键的单例缓存无上限 | 超过 20,000 条即清空重建 |

修复后经**实测复验**（真实 Kestrel + curl，独立于测试套件）：口令重置后旧刷新令牌兑换 400、旧访问令牌访问权限端点 403、旧访问令牌访问仅认证端点（userinfo/`/api/me`）403、新口令登录 200；委派管理员自授 `auth.admin.**` 被 403 拦截并提示所缺权限；非法权限码 400。全解决方案 `dotnet build` 0 错误 0 警告；单元 163/163、集成 41/41 全绿；6 个 Release NuGet 包正常产出。

**评审方法本身**：34 个评审 agent（4 finder + 30 verifier）、约 182 万 token、567 次工具调用，全程自动化对抗验证，避免"看似合理实则不可触发"的伪发现进入修复清单。

### 6.1 第二轮：逐组件三维对抗验证（功能/性能/设计）

对 10 个组件各派 agent 从**功能正常 / 性能最优 / 设计完整**三维对抗验证。新发现的真实问题已全部修复并配回归测试与实测：

| 维度 | 问题 | 修复 |
|---|---|---|
| 功能/安全 | `Pbkdf2PasswordHasher.Verify` 对空派生密钥段返回 true（畸形哈希→口令校验绕过） | 拒绝空盐/空密钥的退化哈希（正常哈希不受影响） |
| 功能/安全 | 仅持 `ManageRoles` 者可建 `auth.admin.**` 角色再自赋而提权 | CreateRole/UpdateRole 授予权限需 `ManagePermissions` |
| 功能/安全 | 仅持 `ManageClients` 者可建 `auth.admin.**` 客户端换令牌提权 | CreateClient/UpdateClient 设权限需 `ManagePermissions` + 校验权限码 |
| 功能/安全 | 经 API 改 `IsSystem=false` 绕过系统角色删除保护 | 角色写接口忽略 `IsSystem`（仅种子/迁移可设） |
| 设计/安全 | 登录表单无 CSRF 防护（会话强制登入） | POST /account/login 校验 Origin/Referer 同源 |
| 设计/安全 | SSO Cookie `Secure` 绑定 `Request.IsHttps`，TLS 终止代理下明文下发 | 新增 `SsoCookieSecurePolicy` 配置项 |
| 设计/安全 | 删除客户端遗留其未过期刷新令牌 | 新增 `ITokenStore.RevokeClientRefreshTokensAsync`，DeleteClient 调用 |
| 性能/DoS | 管理面板静态资源缓存无上限（游客无限路径→OOM） | 白名单嵌入资源名，未知路径 404 不入缓存 |
| 性能 | 客户端 `GetAccessTokenAsync` 有效令牌仍进信号量 | 无锁快路径 |
| 性能 | 并发 401 各自 `RefreshAsync` 造成刷新惊群 | `RefreshIfCurrentAsync` 合并（令牌未变才刷新） |
| 性能 | `JwtTokenService` 每次校验/JWKS 请求重复分配 | `TokenValidationParameters` 与 JWKS JSON 构建一次复用 |
| 性能 | 存储读路径 JSON 序列化深拷贝 | `AuthUser`/`AuthRole` 手写深拷贝（快约一个数量级） |
| 设计/合规 | OAuth 错误响应缺 `Cache-Control:no-store`（RFC 6749 §5.2） | 错误响应补 no-store/no-cache |
| 设计/文档 | CORS/存储抽象/`EnsureClientAsync` 文档与实现不符 | 文档订正（CORS 需宿主 UseCors、自定义存储单例约束、方法摘要） |

被反驳/判为主观或已接受设计的候选（如"自省端点允许任一已认证客户端"符合 RFC 7662、"缓存满 Clear"策略合理等）未纳入修复。

修复后复验：全解决方案 build 0 错误 0 警告；单元 **169/169**、集成 **45/45** 全绿；6 个 Release 包正常产出；新增安全修复经真实 Kestrel + curl 实测（登录 CSRF 跨站 400/同源 302、OAuth 错误 no-store、静态未知路径 404、角色/客户端提权 403）。

**性能复测确认无回退且有提升**：判断热路径仍为 19–24 ns（3,653×–373,614× 于 1.x）；`AuthUser`/`AuthRole` 手写深拷贝把缓存未命中的首次构建成本从 0.74 ms 降至 **0.16 ms**（约 4.6×，因替换了存储读路径的 JSON 深拷贝往返）。

## 6.2 生产集群落地

新增 `Cyaim.Authentication.EntityFrameworkCore` 包，把集群从"设计"落到"可运行"：

- **EF Core 共享数据库存储**（`EntityFrameworkAuthStore`）：经 `IDbContextFactory` 以单例实现全部数据存储接口（供单例评估器安全使用）；令牌一次性消费用条件 `UPDATE ... WHERE ConsumedAt IS NULL` 的受影响行数实现**数据库级原子性**；提供程序无关（Npgsql/SqlServer/Sqlite）。
- **数据库单行集群版本**（`EfClusterVersionStore`）：`UPDATE ... SET Version = Version + 1` 原子递增——集群**只需共享一个数据库、无需 Redis**。
- **一行装配** `AddCyaimAuthEntityFrameworkStores(db => db.UseNpgsql(...))`；可运行示例 `samples/Sample.Cluster`。
- **非 EF 支持**：存储接口不绑定 EF，文档给出 SqlSugar / Dapper / ADO.NET 的原生 SQL 蓝图（两个原子操作）。

验证证据：

| 验证 | 结果 |
|---|---|
| EF 存储契约测试（CRUD/唯一性/原子消费/授权码/清理/版本递增） | 6/6 通过 |
| **两实例共享 SQLite 集成测试** | 通过：① 共享数据可见性；② 令牌一次性消费跨实例原子（A 轮换后 B 重放旧令牌被拦截并吊销家族）；③ 权限变更跨实例缓存失效（A 改角色 → B 轮询后重建读到新权限） |
| **真实两实例 HTTP 实测**（Sample.Cluster，两进程共享一个 SQLite 文件） | 通过：改权限前两实例 `clusterVersion=7`；在实例 A 经管理 API 改角色权限 → A 立即 `8`、B 仍 `7`；约 3 秒轮询后 B 追上 `8`。跨实例缓存失效经真实 HTTP 确认 |

## 7. 目标达成对照

| 目标 | 状态 | 证据 |
|---|---|---|
| 对齐权限标准 | ✅ | [docs/standards-alignment.md](docs/standards-alignment.md)；§2/§4 语义测试 |
| 易用性 | ✅ | 一行接入（README 30 秒上手）；[docs/getting-started.md](docs/getting-started.md) 五场景 |
| 权限判断性能 | ✅ | §3：ns 级判断、数千倍于 1.x |
| 对标 ID5 | ✅ | [docs/id5-parity.md](docs/id5-parity.md)；§4.2 协议验证 |
| ASP.NET Core / WASM / WebSocket 集成 | ✅ | §4.1；samples/Sample.Wasm |
| WinForms/WPF 支撑 | ✅ | Client SDK（netstandard2.0）+ samples/Sample.Wpf |
| 统一登录 | ✅ | §4.2 SSO 流程（13–16、26） |
| 独立权限管理面板 | ✅ | AdminPanel 包 + §4.2 管理 API 验证 |
| 1.x 兼容 | ✅ | Obsolete 保留；[docs/migration-1x.md](docs/migration-1x.md) |
