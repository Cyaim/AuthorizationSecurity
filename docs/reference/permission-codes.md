# 权限代码语法

> 权限代码的规范化规则、通配符匹配语义与示例。面包屑：[文档中心](../README.md) / 参考

权限代码是分层字符串，用于标注端点所需权限、以及给用户/角色/客户端授予权限。语义参考 Apache Shiro 的通配符权限，并采用 **拒绝优先（deny-override）**。实现见 `src/Cyaim.Authentication.Abstractions/Permissions/PermissionCode.cs`。

## 规范化规则

任何代码在使用前都会被规范化：

1. **去首尾空白**。
2. **分隔符统一**：`.`（点）与 `:`（冒号）等价，规范化后统一为 `.`。例如 `sys:user.read` → `sys.user.read`。
3. **大小写不敏感**：全部转小写。`Sys.User.Read` → `sys.user.read`。
4. **段字符限制**：每段由字母、数字、`_`、`-` 组成；或整段为通配符 `*` / `**`。

非法代码（空、空段、含非法字符、部分通配如 `us*`、`**` 不在末段）会被拒绝：
- 端点标注中非法 → 该端点 fail-closed（拒绝所有访问）；
- 管理 API 写入非法 → 返回 400；
- 授予数据中若混入非法代码 → 该条被忽略（只会收紧权限，不会放宽）。

## 通配符

| 通配符 | 含义 | 位置约束 |
|---|---|---|
| `*` | 匹配**恰好一个**段 | 可在任意段 |
| `**` | 匹配**零个或多个**段 | **仅允许作为最后一段** |

## 匹配示例

授予的模式 → 是否命中被判断的代码：

| 授予模式 | `a` | `a.b` | `a.b.c` | `a.x.c` |
|---|:--:|:--:|:--:|:--:|
| `a.b` | ✗ | ✓ | ✗ | ✗ |
| `a.*` | ✗ | ✓ | ✗ | ✗ |
| `a.**` | ✓ | ✓ | ✓ | ✗ |
| `a.*.c` | ✗ | ✗ | ✓ | ✓ |
| `**`（`AuthConstants.AllPermissions`） | ✓ | ✓ | ✓ | ✓ |

要点：

- `a.*` 只匹配**下一层的一个段**，不匹配 `a` 本身，也不匹配更深的 `a.b.c`。
- `a.**` 匹配 `a` 及其**全部后代**（零或多段）。给某模块管理员授 `sys.user.**` 即可访问该模块下任意深度端点。
- `*` 可出现在中间段：`a.*.c` 匹配 `a.<任意一段>.c`。

## 拒绝优先（Deny-Override）

一个主体的有效权限 = （直接授予 ∪ 角色层级授予的允许）− 拒绝。**同一代码同时命中允许与拒绝时，结果为拒绝。** 拒绝对通配符同样生效：

```
allow: sys.order.**
deny:  sys.order.delete
```

- `sys.order.read` → 允许
- `sys.order.delete` → **拒绝**（deny 覆盖了 allow 的通配）

这与 XACML 的 deny-overrides 组合算法语义一致，可用于在宽泛授权上开"例外口子"（如受限管理员）。

## 命名建议

- 用业务含义分层，不要绑定控制器名：`sys.user.read`、`order.invoice.export`。
- 首段作为应用/模块前缀，便于批量授权（`sys.**`）。
- 管理面板内置权限见 `AuthConstants.AdminPermissions`：`auth.admin.**`、`auth.admin.users`、`auth.admin.roles`、`auth.admin.permissions`、`auth.admin.clients`、`auth.admin.audit`、`auth.admin.read`。

## 相关 API

- `PermissionCode.Normalize(code)` / `TryNormalize(code, out normalized, out error)`
- `PermissionQuery.Parse(code)` / `TryParse` —— 预解析为查询，热路径零解析开销
- `CompiledPermissionSet.Build(allowCodes, denyCodes?)` / `.IsGranted(query)` / `.Evaluate(query)`

## 相关文档

- [权限模型（概念）](../concepts/permission-model.md)
- [保护 ASP.NET Core API](../guides/protect-aspnetcore.md)
- [公开 API 参考](api.md)
