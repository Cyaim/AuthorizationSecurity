# 从 1.x 迁移到 2.0

> 面包屑：[文档中心](README.md) / 迁移

1.x 的 API 在 2.0 中全部保留并标记 `[Obsolete]`，现有代码可编译运行，但建议尽快迁移。

## 对照表

| 1.x | 2.0 |
|---|---|
| `services.ConfigureAuth(x => ...)` | `services.AddCyaimAuthentication(o => ...).AddInMemoryStore()` |
| `app.UseAuth(x => ...)` | `app.UseCyaimAuthentication()` |
| `[AuthEndPoint()]` | `[RequirePermission("模块.资源.动作")]` |
| `[AuthEndPoint(allowGuest: true)]` | `[AllowGuest]` |
| `[AuthEnableRegex("正则")]` | 通配符权限代码：`sys.user.*`、`sys.**` |
| `AuthOptions.ExtractDatabaseAuthEndPoints` 委托 | 实现 `IUserStore`/`IRoleStore` 等存储接口（或用内置 InMemory/JSON 存储） |
| `AuthOptions.PreAccessEndPointKey` 前缀 | 权限代码首段（如 `sys.`） |
| `ParameterLocation.Header/Query/Cookie` 凭据位置 | `CyaimAuthOptions.AllowTokenFromQuery/AllowTokenFromCookie`（Bearer 头默认启用） |
| Redis/PostgreSQL 手写查询（README 示例） | 任意存储实现 6 个接口即可；权限判断结果自动缓存并按版本失效 |

## 语义差异（重要）

1. **权限节点命名**：1.x 是 `前缀:Controller.Action`；2.0 是分层权限代码，与路由解耦。建议按业务含义命名（`sys.user.read`），不再绑定控制器名。
2. **判断主体**：1.x 只看"凭据串"；2.0 解析 JWT 得到主体（用户/客户端/游客），支持角色层级与拒绝授权。
3. **性能**：1.x 每请求 LINQ 线性扫描；2.0 编译权限集 O(1) 哈希/O(段数) 通配匹配（见 [benchmark-results.md](benchmark-results.md)）。
4. **令牌**：1.x 不管令牌来源；2.0 内置 JWT 签发与校验，也可只用引擎、令牌自理（实现 `ITokenService` 替换）。

## 渐进迁移路径

1. 升级包到 2.0 —— 旧代码照常工作（出现 Obsolete 警告）。
2. 新端点用 `[RequirePermission]` 标注；`AddCyaimAuthentication` 与旧 `ConfigureAuth` 可共存（两套中间件独立）。
3. 把用户/角色数据接入 `IUserStore`/`IRoleStore`（或先用 `AddJsonFileStore` 过渡）。
4. 移除 `UseAuth`/`ConfigureAuth` 与全部 `[AuthEndPoint]`。
