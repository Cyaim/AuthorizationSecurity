# 管理 API 参考

> 权限管理面板（AdminPanel）的 REST API：每个端点的方法、所需权限、请求与响应。面包屑：[文档中心](../README.md) / 参考

管理 API 由 `app.MapCyaimAuthAdmin()` 挂载在 `CyaimAuthAdminOptions.BasePath`（默认 `/auth-admin`）下的 `/api` 前缀。下文用 `{base}` 表示 `BasePath`（即 `/auth-admin`）。SPA 前端就调用这些接口，你也可以直接用它们做自动化管理。

- **认证**：除 `GET {base}/api/config` 匿名外，全部要求携带有效访问令牌（`Authorization: Bearer <token>`），并由权限中间件按下表权限判断。
- **权限**：管理权限常量见 `AuthConstants.AdminPermissions`：`auth.admin.**`（All）、`auth.admin.read`（Read）、`auth.admin.users`（ManageUsers）、`auth.admin.roles`（ManageRoles）、`auth.admin.permissions`（ManagePermissions）、`auth.admin.clients`（ManageClients）、`auth.admin.audit`（ReadAudit）。“任一”表示满足其中之一即可。
- **响应格式**：JSON，属性名 camelCase，枚举序列化为字符串。
- **错误语义**：400（请求非法/权限代码非法/存储约束）、403（缺少所需管理权限；含职责分离守卫）、404（对象不存在）、409（创建时唯一性冲突）。详见[判断原因与错误码](decisions-and-errors.md)。

源码：`src/Cyaim.Authentication.AdminPanel/AdminApi/AdminApiEndpoints.cs`、`AdminDtos.cs`。

---

## 端点一览

| 方法 | 路径 | 所需权限 |
|---|---|---|
| GET | `{base}/api/config` | 匿名 |
| GET | `{base}/api/me` | 仅要求已认证 |
| GET | `{base}/api/stats` | Read 或任一 Manage 权限 |
| GET | `{base}/api/users` | Read 或 ManageUsers |
| POST | `{base}/api/users` | ManageUsers（+ 授予角色需 ManageRoles、授予权限需 ManagePermissions） |
| PUT | `{base}/api/users/{id}` | ManageUsers（同上职责分离） |
| POST | `{base}/api/users/{id}/reset-password` | ManageUsers |
| DELETE | `{base}/api/users/{id}` | ManageUsers |
| GET | `{base}/api/roles` | Read 或 ManageRoles |
| POST | `{base}/api/roles` | ManageRoles（+ 授予权限需 ManagePermissions） |
| PUT | `{base}/api/roles/{id}` | ManageRoles（同上） |
| DELETE | `{base}/api/roles/{id}` | ManageRoles |
| GET | `{base}/api/permissions` | Read 或 ManagePermissions |
| POST | `{base}/api/permissions` | ManagePermissions |
| DELETE | `{base}/api/permissions/{code}` | ManagePermissions |
| GET | `{base}/api/clients` | Read 或 ManageClients |
| POST | `{base}/api/clients` | ManageClients（+ 授予权限需 ManagePermissions） |
| PUT | `{base}/api/clients/{id}` | ManageClients（同上） |
| POST | `{base}/api/clients/{id}/regenerate-secret` | ManageClients |
| DELETE | `{base}/api/clients/{id}` | ManageClients |
| GET | `{base}/api/audit` | ReadAudit |

---

## 配置与当前主体

### GET {base}/api/config （匿名）

SPA 启动配置。返回 `{ tokenEndpoint, clientId, serverName }`（来自 `CyaimAuthAdminOptions`）。

### GET {base}/api/me

当前主体信息与其管理权限判定，SPA 据此显示/隐藏菜单。

```json
{
  "id": "…", "name": "管理员", "subjectType": "User", "isAuthenticated": true,
  "roles": ["admin"], "clientId": null,
  "permissions": { "read": true, "manageUsers": true, "manageRoles": true,
                   "managePermissions": true, "manageClients": true, "readAudit": true }
}
```

### GET {base}/api/stats

仪表盘统计：`{ users, roles, clients, permissions, recentDenied: [最近10条拒绝审计] }`。

---

## 用户

### GET {base}/api/users?search=&skip=&take=

分页列出用户。返回 `{ total, items: [UserDto] }`。`UserDto` **绝不含** `passwordHash` / `securityStamp`：

```
UserDto { id, userName, displayName?, email?, isEnabled, lockoutEnd?,
          roles[], directPermissions[], deniedPermissions[], createdAt, updatedAt }
```

### POST {base}/api/users

创建用户。请求体 `CreateUserRequest`：

```json
{ "userName": "alice", "password": "S3cret!", "displayName": "Alice",
  "email": "a@x.com", "roles": ["order-admin"],
  "directPermissions": ["sys.report.read"], "deniedPermissions": [] }
```

- `userName`、`password` 必填。
- **职责分离**：请求带非空 `roles` 需调用者具备 `ManageRoles`；带非空 `directPermissions`/`deniedPermissions` 需 `ManagePermissions`，否则 403。
- 非法权限代码 → 400。用户名冲突 → 409。成功 → 201 + `UserDto`。

### PUT {base}/api/users/{id}

更新用户（`UpdateUserRequest`，null 字段保持不变，不含密码）：

```json
{ "displayName": "…", "email": "…", "roles": [...],
  "directPermissions": [...], "deniedPermissions": [...], "isEnabled": true }
```

- 同样的职责分离守卫与权限代码校验。
- 授权字段变化或将 `isEnabled` 置为 false 时会**轮换安全戳**；禁用账户会**吊销其刷新令牌**（旧访问令牌下次判断即失效）。
- 成功 → 200 + `UserDto`。

### POST {base}/api/users/{id}/reset-password

重置密码。请求体 `{ "newPassword": "…" }`。成功轮换安全戳并**吊销该用户全部刷新令牌**（旧会话失效）。成功 → 204。

### DELETE {base}/api/users/{id}

删除用户并吊销其刷新令牌。成功 → 204。

---

## 角色

### GET {base}/api/roles

返回全部角色（`AuthRole`：`id, name, displayName?, description?, parentRoles[], permissions[], deniedPermissions[], isSystem, createdAt, updatedAt`）。

### POST {base}/api/roles ｜ PUT {base}/api/roles/{id}

创建/更新角色。请求体 `RoleRequest`（更新时 null 字段不变）：

```json
{ "name": "order-admin", "displayName": "订单管理", "description": "…",
  "parentRoles": ["order-viewer"], "permissions": ["order.**"], "deniedPermissions": ["order.delete"] }
```

- **职责分离**：带非空 `permissions`/`deniedPermissions` 需 `ManagePermissions`。
- 非法权限代码 → 400；名称冲突 → 409。
- `isSystem` 字段被**忽略**（系统角色只能由种子/迁移设定，防止绕过删除保护）。

### DELETE {base}/api/roles/{id}

删除角色。系统内置角色（`isSystem=true`）不可删除 → 400。

---

## 权限定义

### GET {base}/api/permissions

返回权限定义列表（`PermissionDefinition`：`code, displayName?, description?, group?, origin, createdAt`）。

### POST {base}/api/permissions

批量登记/更新权限定义。请求体为数组：

```json
[ { "code": "sys.user.read", "displayName": "查看用户", "group": "用户管理" } ]
```

代码经规范化校验，非法 → 400。成功 → 204。

### DELETE {base}/api/permissions/{code}

删除一条权限定义。成功 → 204。

---

## 客户端

### GET {base}/api/clients

返回 `ClientDto[]`（不含密钥哈希，含 `hasSecret: bool`）：

```
ClientDto { clientId, clientName?, hasSecret, allowedGrantTypes[], redirectUris[],
            postLogoutRedirectUris[], allowedScopes[], permissions[], requirePkce,
            allowOfflineAccess, accessTokenLifetimeSeconds, refreshTokenLifetimeSeconds,
            authorizationCodeLifetimeSeconds, enabled, allowedCorsOrigins[], createdAt, updatedAt }
```

### POST {base}/api/clients ｜ PUT {base}/api/clients/{id}

创建/更新客户端。请求体 `ClientRequest`：

```json
{ "clientId": "web-app", "clientName": "Web 应用", "secret": "…",
  "allowedGrantTypes": ["authorization_code", "refresh_token"],
  "redirectUris": ["https://app/callback"], "allowedScopes": ["permissions", "offline_access"],
  "permissions": [], "requirePkce": true, "allowOfflineAccess": true }
```

- `secret` 语义：创建时有值则哈希存储；**更新时 null=不变、空串=清除、有值=更新**。
- **职责分离**：带非空 `permissions`（客户端凭据模式授予令牌的权限）需 `ManagePermissions`，且校验权限代码。
- 创建 clientId 冲突 → 409。

### POST {base}/api/clients/{id}/regenerate-secret

重新生成客户端密钥。返回 `{ "secret": "<明文>" }`（**仅此一次返回明文**，存储只保留哈希）。

### DELETE {base}/api/clients/{id}

删除客户端，并**吊销其已签发的全部刷新令牌**。成功 → 204。

---

## 审计

### GET {base}/api/audit?category=&outcome=&subjectId=&from=&to=&skip=&take=

按条件查询审计事件（倒序）。过滤参数：`category`（`Login`/`Logout`/`TokenIssued`/`TokenRevoked`/`PermissionCheck`/`Admin`/`Security`，忽略大小写或数字）、`outcome`（`Success`/`Denied`/`Failure`）、`subjectId`、`from`/`to`（时间）、`skip`/`take`（默认 50、上限 1000）。返回 `{ items: [AuditEvent] }`。

---

## 相关文档

- [使用权限管理面板（指南）](../guides/admin-panel.md)
- [判断原因与错误码](decisions-and-errors.md)
- [公开 API 参考](api.md)
- [权限代码语法](permission-codes.md)
