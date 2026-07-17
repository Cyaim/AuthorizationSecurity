# 权限模型

> 一句话：Cyaim.Authentication 用分层通配符权限代码统一表达权限，通过 RBAC（角色层级继承）与 ABAC（命名策略）两条途径授予，最终编译为一个「拒绝优先」的不可变权限集并按版本 + TTL 缓存。

[文档中心](../README.md) / 概念

- 上一层概念：[架构总览](./architecture.md)、[令牌与会话](./tokens-and-sessions.md)
- 语法速查：[权限代码语法参考](../reference/permission-codes.md)
- 相关指南：[自定义 ABAC 策略](../guides/custom-policies.md)、[判断原因与错误码参考](../reference/decisions-and-errors.md)

## 权限代码语法

权限代码是分层字符串，规范与解析在 `src/Cyaim.Authentication.Abstractions/Permissions/PermissionCode.cs`。

- **分层**：段之间用分隔符连接，如 `sys.user.read`。
- **分隔符等价**：`.`（规范分隔符）与 `:`（兼容 1.x 的 `Prefix:Controller.Action` 风格）等价，规范化后统一为 `.`。例如 `sys:user.read` → `sys.user.read`。
- **大小写不敏感**：规范化会转小写。`Sys.User.Read` 与 `sys.user.read` 等价。
- **合法字符**：每段允许字母、数字、`_`、`-`，或整段为通配符。空段（如 `sys..read`）非法。
- **通配符**（必须独占一段）：
  - `*` 匹配**恰好一个**段。
  - `**` 匹配**零个或多个**段，**仅允许作为最后一段**。
  - `sys.us*` 这类「部分匹配」非法，会被 `TryNormalize` 拒绝。

规范化 API：

```csharp
using Cyaim.Authentication.Abstractions.Permissions;

string code = PermissionCode.Normalize("Sys:User.Read");   // => "sys.user.read"

if (PermissionCode.TryNormalize("sys.user.*", out string normalized))
{
    // normalized == "sys.user.*"
}

bool hasWildcard = PermissionCode.HasWildcard("sys.user.*"); // true
```

### 匹配示例

授予的代码可含通配符；查询（端点要求或命令式判断）应为具体节点。匹配语义如下：

| 授予（模式） | 查询代码 | 是否命中 | 说明 |
| --- | --- | --- | --- |
| `sys.user.read` | `sys.user.read` | ✅ | 精确命中 |
| `sys.user.read` | `sys.user.write` | ❌ | 不同叶子 |
| `sys.user.*` | `sys.user.read` | ✅ | `*` 匹配一段 |
| `sys.user.*` | `sys.user.profile.read` | ❌ | `*` 只匹配一段，不跨层 |
| `sys.**` | `sys` | ✅ | `**` 匹配零段 |
| `sys.**` | `sys.user.profile.read` | ✅ | `**` 匹配任意后代 |
| `sys.*.read` | `sys.user.read` | ✅ | 中间段通配 |
| `sys.*.read` | `sys.user.write` | ❌ | 末段不符 |
| `**` | 任意合法代码 | ✅ | `AuthConstants.AllPermissions`，全权限 |

> `sys:user.read` 与 `sys.user.read` 因分隔符等价、大小写规范化，命中结果完全相同。

### 拒绝优先（Deny-Override）

同一主体的有效权限集里，只要某查询命中一条**拒绝**规则，无论是否也命中允许规则，结果都是拒绝。评估顺序见 `CompiledPermissionSet.Evaluate`（`src/Cyaim.Authentication.Abstractions/Permissions/CompiledPermissionSet.cs`）：

```csharp
// 伪代码，对应 CompiledPermissionSet.Evaluate(in PermissionQuery)
if (exactDenies.Contains(code) || wildcardDenies.Matches(query))
    return PermissionEffect.Deny;      // 拒绝优先
if (exactAllows.Contains(code) || wildcardAllows.Matches(query))
    return PermissionEffect.Allow;
return PermissionEffect.NotSet;         // 未命中任何规则
```

因此给角色授予 `sys.**` 再对个别用户拒绝 `sys.user.delete`，该用户即可用其余全部 `sys.*` 权限，唯独删不了用户。拒绝规则可来自用户、角色或其父角色的 `DeniedPermissions`。

匹配实现细节：精确代码放入 `HashSet`（`O(1)`），含通配符的模式放入 `PermissionTrie` 字典树（`O(段数)`，`*` 回溯时最坏 `O(段数 × 分支数)`），非法代码在编译期被静默忽略（坏数据只会收紧权限，不会阻断鉴权）。

## RBAC：用户 — 角色 — 权限

模型定义在 `src/Cyaim.Authentication.Abstractions/Models/`。

- `AuthUser`（`AuthUser.cs`）：`Roles`（角色名列表）、`DirectPermissions`（直接允许）、`DeniedPermissions`（直接拒绝）。
- `AuthRole`（`AuthRole.cs`）：`Permissions`（允许）、`DeniedPermissions`（拒绝）、`ParentRoles`（父角色名，继承其允许与拒绝）。

主体的有效权限 = 直接授权 ∪ 所属角色（含祖先角色）授权，减去所有来源的拒绝。

### 角色层级继承（BFS，环安全）

角色通过 `ParentRoles` 继承父角色权限（NIST RBAC1）。展开在 `PermissionEvaluator.FlattenRolesAsync`（`src/Cyaim.Authentication.Core/Engine/PermissionEvaluator.cs`）用**广度优先遍历**完成，并用 `visited` 集合去重——因此**角色环（A→B→A）会被安全忽略**，不会死循环或重复计入：

```csharp
// 对应 FlattenRolesAsync 的核心逻辑
var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var queue = new Queue<string>();
foreach (var name in roleNames)
    if (visited.Add(name)) queue.Enqueue(name);

while (queue.Count > 0)
{
    var role = graph.ByName[queue.Dequeue()];
    allows.AddRange(role.Permissions);
    denies.AddRange(role.DeniedPermissions);
    foreach (var parent in role.ParentRoles)
        if (visited.Add(parent)) queue.Enqueue(parent);   // 已访问不再入队 => 环安全
}
```

角色名不区分大小写（`RoleGraph.ByName` 用 `OrdinalIgnoreCase`）。

### NIST RBAC 层级对应

| NIST 级别 | 能力 | 框架支持 |
| --- | --- | --- |
| RBAC0（Core） | 用户 — 角色 — 权限的多对多分配 | `AuthUser.Roles` + `AuthRole.Permissions` |
| RBAC1（Hierarchical） | 角色继承（父角色权限传递给子角色） | `AuthRole.ParentRoles`，BFS 展开、环安全 |
| RBAC2（Constraints） | 约束（如职责分离 SoD） | 管理面板对「设置角色/权限/客户端权限」施加职责分离——需对应 `Manage` 权限，见 [管理 REST API 参考](../reference/admin-api.md) |

## ABAC：命名策略

RBAC 回答「你是谁、有什么角色」，ABAC 回答「在什么条件下」。策略是 Abstractions 中的 `IAuthPolicy`（`src/Cyaim.Authentication.Abstractions/Authorization/AuthorizationContext.cs`）：

```csharp
public interface IAuthPolicy
{
    string Name { get; }   // 唯一，不区分大小写
    Task<bool> EvaluateAsync(AuthorizationContext context, CancellationToken cancellationToken = default);
}
```

`AuthorizationContext` 提供主体 `Subject`、被判断的 `PermissionCode`、`Items`（资源/环境属性）、`UnderlyingContext`（ASP.NET Core 下即 `HttpContext`）、评估时刻 `Now`。

注册方式（委托或类型）：

```csharp
builder.Services.AddCyaimAuthentication(o => { /* ... */ })
    .AddInMemoryStore()
    .AddPolicy("working-hours", ctx => ctx.Now.LocalDateTime.Hour is >= 9 and < 18)  // 同步委托
    .AddPolicy<OwnerOnlyPolicy>();                                                    // 策略类型
```

### 与权限码组合

策略可与权限码同时要求（「且」关系）。策略不存在按拒绝处理（`PolicyNotFound`），策略内部抛异常按拒绝处理（fail-closed，`PolicyNotSatisfied`）——见 `PermissionEvaluator.EvaluatePolicyAsync`。

```csharp
// Minimal API：先要求权限码，再要求策略
app.MapPost("/api/transfer", () => "...")
   .RequirePermission("finance.transfer")
   .RequireAuthPolicy("working-hours");
```

```csharp
// 特性：单个特性内 Policy 与权限码同时要求
[RequirePermission("finance.transfer", Policy = "working-hours")]
public IActionResult Transfer() => Ok();
```

编写策略的完整示例见 [自定义 ABAC 策略](../guides/custom-policies.md)。

## 有效权限如何编译与缓存

评估器为每个主体构建一次不可变的 `CompiledPermissionSet` 并缓存，热路径命中时是纯同步查找、零分配。逻辑见 `PermissionEvaluator`（`BuildEntryAsync` / `GetOrBuildEntryAsync` / `TryGetValidEntry`）。

### 编译（BuildEntryAsync）

按主体类型收集允许 / 拒绝代码，然后 `CompiledPermissionSet.Build(allows, denies, version)`：

- **用户**（有 `IUserStore`）：读存储中的用户。禁用 / 锁定 / 令牌安全戳与存储不一致 → 标记 `SubjectDisabled`（权限集置空）。否则取用户 `DirectPermissions` / `DeniedPermissions` 与其 `Roles`。**存储数据优先于令牌声明**，支持实时授权变更。本地查无此用户（分布式资源服务场景）时回退信任令牌声明。
- **客户端**（有 `IClientStore`）：读 `ClientApplication`，禁用则 `SubjectDisabled`，否则取 `client.Permissions`。
- **游客 / 其他**：使用主体自带的 `DirectPermissions` / `DeniedPermissions`；未认证且配置了 `GuestRoles` 时并入游客角色。
- 最后对全部角色名做 `FlattenRolesAsync`（含祖先角色）合并允许与拒绝。

### 缓存键、版本与 TTL 失效

缓存有效性由三者共同决定（`TryGetValidEntry`）：缓存键匹配、`entry.Version == 存储当前版本`、且未超过 TTL。

- **缓存键**（`BuildCacheKey`）：
  - 用户：`u|<用户Id>|<安全戳>` —— 安全戳一变，旧缓存自然失效。
  - 客户端：`c|<客户端Id>`。
  - 游客：`g|<角色名逗号拼接>`。
- **版本戳**：`IAuthStoreVersion.Version`。任何写操作（用户/角色/客户端/权限变更）应递增版本，使全部缓存条目失效 —— 实现实时授权变更。
- **TTL**：`CyaimAuthCoreOptions.PermissionCacheTtl`（默认 5 分钟）。即便版本未变，条目过期也会重建，兜底外部数据漂移。
- **容量上限**：缓存数超过 `MaxCachedPermissionSets`（默认 10000）时整体清空（`InvalidateAll` 可手动清空，批量导入后可调用）。
- 角色图 `RoleGraph` 单独按版本 + TTL 缓存，避免每次判断重复读全部角色。

三重失效叠加起来的效果：**安全戳失效**（口令重置/账户变更，令牌级）、**版本失效**（任意授权数据变更，全局）、**TTL 失效**（兜底），保证授权变更能及时生效。安全戳机制的令牌侧细节见[令牌与会话](./tokens-and-sessions.md#安全戳失效机制)。

### 判断结论

`EvaluateAsync` 把 `PermissionEffect` 映射为 `AuthorizationDecision`（`src/Cyaim.Authentication.Abstractions/Authorization/AuthorizationDecision.cs`）：

| 权限效果 / 状态 | 结论原因 `AuthorizationReason` |
| --- | --- |
| `SubjectDisabled` | `SubjectDisabled` (13) |
| `Allow` | `Granted` (0) |
| `Deny` | `DeniedByRule` (11) |
| `NotSet`（已认证） | `NoMatchingGrant` (10) |
| `NotSet`（游客） | `GuestNotAllowed` (12) |

策略侧另有 `GrantedByPolicy`(1)、`PolicyNotSatisfied`(14)、`PolicyNotFound`(15)。完整枚举与 HTTP 映射见 [判断原因与错误码参考](../reference/decisions-and-errors.md)。

命令式判断：

```csharp
// 注入 IPermissionEvaluator
AuthorizationDecision d = await evaluator.EvaluateAsync(subject, "sys.order.export");
if (!d.IsGranted) Console.WriteLine(d.Reason);   // 例如 NoMatchingGrant

bool ok = await evaluator.IsGrantedAsync(subject, "sys.order.export");  // 仅布尔
```

在 ASP.NET Core 里也可直接用 `HttpContext.CheckPermissionAsync(code)` / `HasPermissionAsync(code)`。

## 相关文档

- [权限代码语法参考](../reference/permission-codes.md) —— 语法速查表
- [架构总览](./architecture.md) —— 请求鉴权数据流
- [令牌与会话](./tokens-and-sessions.md) —— 安全戳、`perm` 声明
- [自定义 ABAC 策略](../guides/custom-policies.md)
- [判断原因与错误码参考](../reference/decisions-and-errors.md)
- [配置项参考](../reference/configuration.md) —— `PermissionCacheTtl`、`MaxCachedPermissionSets`
