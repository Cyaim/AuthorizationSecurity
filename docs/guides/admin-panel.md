# 使用权限管理面板

> Cyaim.Authentication.AdminPanel 是一个内嵌的单页管理后台，挂到应用后即可在浏览器里可视化管理用户、角色、权限、客户端并查看审计日志——零额外前端工程。

[文档中心](../README.md) / 指南（Guides）

管理面板是一个随包发布的 SPA + 一组管理 REST API，两者挂载在同一个 `BasePath` 前缀下。它本身也用框架的权限体系保护——谁能进面板、能改什么，取决于其 `auth.admin.*` 权限。本篇讲怎么挂载、怎么登录、每页能做什么，以及背后的权限模型。逐个 REST 端点的请求/响应速查见 [管理 API 参考](../reference/admin-api.md)。

---

## 挂载面板

管理面板依赖核心引擎与存储，因此要先 `AddCyaimAuthentication(...)`。面板需要有令牌端点来登录——通常与 [授权中心](auth-server-sso.md) 跑在同一应用（`AddCyaimAuthServer` 提供 `/connect/token`）。

```xml
<PackageReference Include="Cyaim.Authentication.AdminPanel" Version="2.0.0" />
```

```csharp
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Core;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "https://auth.example.com";
    o.HmacSigningKey = "至少32字节的共享签名密钥..........";
}).AddJsonFileStore("data/auth-store.json");

builder.Services.AddCyaimAuthServer();          // 提供面板登录所需的 /connect/token
builder.Services.AddCyaimAuthAdminPanel(o =>
{
    o.ServerName = "示例授权中心";              // 登录页与侧边栏标题
});

var app = builder.Build();

app.UseCyaimAuthentication();  // 面板 API 靠这个中间件鉴权
app.MapCyaimAuthServer();
app.MapCyaimAuthAdmin();       // 挂载面板 SPA + 管理 API

app.Run();
```

`MapCyaimAuthAdmin()` 在 `BasePath` 下挂载两部分（源码：`src/Cyaim.Authentication.AdminPanel/CyaimAuthAdminEndpointRouteBuilderExtensions.cs`）：内嵌 SPA 静态资源，以及前缀为 `{BasePath}/api` 的管理 REST API。

> 面板要能工作，必须存在一个可用于 **password 模式登录** 的客户端（默认 `cyaim-admin-panel`），并至少有一个拥有管理权限的用户。这两者的播种见 [搭建授权中心与统一登录](auth-server-sso.md#用-authdataseeder-播种初始数据)。

---

## 访问与登录

浏览器打开 `/auth-admin`（默认 `BasePath`）。SPA 启动时先匿名请求 `GET /auth-admin/api/config` 拿到令牌端点、客户端 Id 与服务器名，然后提供两种登录方式：

1. **账号口令登录**：输入授权中心的用户名与口令，SPA 走 OAuth 2.0 password 模式向 `TokenEndpoint`（默认 `/connect/token`）用 `ClientId`（默认 `cyaim-admin-panel`）换取访问令牌，之后所有管理 API 调用都带上该令牌。
2. **粘贴令牌登录**：直接粘贴一个已有的访问令牌。适用于面板与授权中心不在同一应用、或用外部工具签发令牌调试的场景。

登录后 SPA 调 `GET /auth-admin/api/me` 得到当前主体及其六项管理权限的布尔值，据此决定侧边栏显示哪些页、哪些按钮可用。

> 面板只是权限体系的一个“客户端”。你能进面板、能操作什么，完全由令牌主体的 `auth.admin.*` 权限决定——没有对应权限的页面和操作即使调用也会被后端拒绝（见下文[权限模型](#管理权限模型与职责分离)）。

---

## 各页功能

| 页面 | 后端端点 | 所需权限 | 能做什么 |
|---|---|---|---|
| **仪表盘** | `GET /api/stats` | `Read` 或任一管理权限 | 用户/角色/客户端/权限计数，最近被拒绝的审计事件 |
| **用户** | `GET/POST /api/users`、`PUT/DELETE /api/users/{id}`、`POST /api/users/{id}/reset-password` | 查看需 `Read` 或 `ManageUsers`；增删改需 `ManageUsers` | 增删改用户、分配角色/直接权限/拒绝权限、启禁用、重置口令 |
| **角色** | `GET/POST /api/roles`、`PUT/DELETE /api/roles/{id}` | 查看需 `Read` 或 `ManageRoles`；增删改需 `ManageRoles` | 增删改角色、设置父角色继承、授予/拒绝权限 |
| **权限** | `GET/POST /api/permissions`、`DELETE /api/permissions/{code}` | 查看需 `Read` 或 `ManagePermissions`；增删需 `ManagePermissions` | 登记/更新/删除权限定义（供各处下拉展示） |
| **客户端** | `GET/POST /api/clients`、`PUT/DELETE /api/clients/{id}`、`POST /api/clients/{id}/regenerate-secret` | 查看需 `Read` 或 `ManageClients`；增删改需 `ManageClients` | 增删改客户端、授权类型/回调地址/作用域、重新生成密钥 |
| **审计** | `GET /api/audit` | `ReadAudit` | 按分类/结果/主体/时间范围查询审计事件 |

行为要点（源码：`src/Cyaim.Authentication.AdminPanel/AdminApi/AdminApiEndpoints.cs`）：

- **禁用或删除用户、重置口令** 会轮换该用户的安全戳并吊销其全部刷新令牌——已签发的会话随即失效，无法续期。安全戳原理见 [令牌与会话](../concepts/tokens-and-sessions.md)。
- **重新生成客户端密钥** 返回的明文只在该次响应出现一次，务必当场保存。
- **权限代码格式校验**：授予的权限/拒绝权限代码若无法规范化会返回 400，避免非法的 deny 规则被静默丢弃而失效。
- **系统角色**（`IsSystem=true`）不能经面板删除，`IsSystem` 也不能经管理 API 改写——防止绕过删除保护。系统角色只由种子/迁移设定。

---

## 管理权限模型与职责分离

面板的每个操作都由一个内置管理权限守卫。这些代码定义在 `AuthConstants.AdminPermissions`（源码：`src/Cyaim.Authentication.Abstractions/AuthConstants.cs`）：

| 常量 | 权限代码 | 含义 |
|---|---|---|
| `All` | `auth.admin.**` | 面板全部权限（超级管理员） |
| `Read` | `auth.admin.read` | 只读查看 |
| `ManageUsers` | `auth.admin.users` | 用户管理 |
| `ManageRoles` | `auth.admin.roles` | 角色管理 |
| `ManagePermissions` | `auth.admin.permissions` | 权限定义管理 |
| `ManageClients` | `auth.admin.clients` | 客户端管理 |
| `ReadAudit` | `auth.admin.audit` | 审计日志查看 |

因为权限代码是分层通配的，给一个角色授予 `auth.admin.**` 即涵盖上面全部；授予 `auth.admin.read` 则只能看不能改。给管理员角色播种权限：

```csharp
await seeder.EnsureRoleAsync("admin",
    new[] { AuthConstants.AdminPermissions.All },
    displayName: "系统管理员", isSystem: true);

// 只读审计员：只能看 + 只能查审计
await seeder.EnsureRoleAsync("auditor",
    new[] { AuthConstants.AdminPermissions.Read, AuthConstants.AdminPermissions.ReadAudit },
    displayName: "审计员");
```

### 职责分离（防纵向越权）

关键设计：**授予权限的操作，要求调用者自己就持有那份管理权限**。这防止一个只有 `ManageUsers` 的委派管理员通过“编辑用户”给自己塞进任意权限而纵向越权。具体守卫（源码 `AdminApiEndpoints.RequireManageAsync`）：

- 创建/编辑用户时**分配角色** → 额外要求调用者具备 `ManageRoles`（`auth.admin.roles`）。
- 创建/编辑用户时**授予直接权限或拒绝权限** → 额外要求 `ManagePermissions`（`auth.admin.permissions`）。
- 创建/编辑角色时**给角色配置权限或拒绝权限** → 额外要求 `ManagePermissions`（否则仅持 `ManageRoles` 者可造一个含 `auth.admin.**` 的角色再自赋）。
- 创建/编辑客户端时**设置 `permissions`**（client_credentials 会直接授予令牌） → 额外要求 `ManagePermissions`。

不满足时返回 `403`，消息形如“该操作涉及授予权限或角色，需要 auth.admin.permissions 权限”。因此发放“能建用户但不能提权”的委派管理员，只给 `ManageUsers` 即可——他能管理用户账户，但无法给任何人（含自己）授予权限或角色。

所有管理写操作都会写入审计（`Category=Admin`），可在审计页追溯。

---

## 配置项

管理面板配置类 `CyaimAuthAdminOptions`（源码：`src/Cyaim.Authentication.AdminPanel/CyaimAuthAdminOptions.cs`）：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `BasePath` | `/auth-admin` | 面板 SPA 与管理 API 的公共前缀 |
| `TokenEndpoint` | `/connect/token` | SPA 登录用的令牌端点；可填其他授权服务器的绝对地址 |
| `ClientId` | `cyaim-admin-panel` | SPA 登录用的客户端 Id |
| `ServerName` | `null` | 登录页与侧边栏标题；为空时 SPA 用默认名 |

把面板对接**独立部署的**授权中心（面板与授权中心不在同一应用）时，只需把 `TokenEndpoint` 指向那台授权中心的绝对地址、`ClientId` 用它上面注册的面板客户端：

```csharp
builder.Services.AddCyaimAuthAdminPanel(o =>
{
    o.BasePath = "/admin";
    o.TokenEndpoint = "https://auth.example.com/connect/token";
    o.ClientId = "cyaim-admin-panel";
    o.ServerName = "示例授权中心";
});
```

此时面板所在应用仍需 `AddCyaimAuthentication` 且与授权中心共享签名密钥/发行者，以便本地验证进来的管理令牌。对接原理同 [资源服务器如何对接](auth-server-sso.md#资源服务器如何对接)。

---

## 相关文档

- [管理 API 参考](../reference/admin-api.md) —— 每个管理 REST 端点的方法、权限、请求/响应
- [搭建授权中心与统一登录](auth-server-sso.md) —— 授权中心组装与数据播种
- [权限模型](../concepts/permission-model.md) —— 权限代码、角色层级、拒绝优先
- [令牌与会话](../concepts/tokens-and-sessions.md) —— 安全戳、刷新令牌吊销原理
- [权限代码语法](../reference/permission-codes.md) —— 通配符与匹配规则
- [判断原因与错误码](../reference/decisions-and-errors.md) —— 被拒时的原因与 HTTP 结果
- [配置参考](../reference/configuration.md) —— 全部配置项与默认值
