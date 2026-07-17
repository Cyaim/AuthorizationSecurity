# Cyaim.Authentication

> 现代 .NET 权限框架：RBAC/ABAC 授权引擎 + OAuth 2.0 / OIDC 兼容授权服务器 + 统一登录（SSO）+ 内嵌权限管理面板 + 跨平台客户端 SDK。

[![NuGet](https://img.shields.io/nuget/v/Cyaim.Authentication.svg)](https://www.nuget.org/packages/Cyaim.Authentication/)

## 能做什么

- **端点权限**：`[RequirePermission("sys.user.read")]` 或 `.RequirePermission(...)` 一行保护控制器、Minimal API、WebSocket
- **RBAC + ABAC**：角色层级继承（NIST RBAC1）、拒绝优先授权、通配符权限码（`sys.user.*`、`sys.**`）、命名策略
- **高性能**：每主体权限编译为哈希 + 字典树，命中路径 O(1)，实测比 1.x 的线性扫描快多个数量级（见 [docs/benchmark-results.md](docs/benchmark-results.md)）
- **统一登录**：内置授权服务器——授权码 + PKCE、客户端凭据、密码、刷新令牌轮换；SSO 会话；发现文档与 JWKS
- **管理面板**：`/auth-admin` 内嵌 SPA，管理用户/角色/权限/客户端并查看审计日志，零前端构建
- **全平台客户端**：WinForms / WPF / Blazor WASM / 控制台共用一个 SDK，自动刷新令牌、本地权限判断门控 UI
- **可观测**：结构化日志（EventId）、System.Diagnostics.Metrics 指标、审计日志（内存 + JSONL）

## 包一览

| 包 | 用途 | 目标框架 |
|---|---|---|
| `Cyaim.Authentication` | ASP.NET Core 集成（中间件、特性、Minimal API 扩展） | net8.0 / net9.0 |
| `Cyaim.Authentication.Abstractions` | 契约与权限匹配引擎，零依赖 | netstandard2.0 / net8.0 |
| `Cyaim.Authentication.Core` | 授权引擎、存储、JWT、审计 | netstandard2.0 / net8.0 / net9.0 |
| `Cyaim.Authentication.Server` | OAuth2/OIDC 授权服务器 + SSO | net8.0 / net9.0 |
| `Cyaim.Authentication.AdminPanel` | 内嵌权限管理面板 | net8.0 / net9.0 |
| `Cyaim.Authentication.Client` | 桌面 / WASM / 服务客户端 SDK | netstandard2.0 / net8.0 |
| `Cyaim.Authentication.EntityFrameworkCore` | EF Core 共享数据库存储 + 集群版本（多实例集群） | net8.0 / net9.0 |

## 30 秒上手

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCyaimAuthentication(o =>
{
    o.Issuer = "my-auth";
    o.Audience = "my-api";
    o.HmacSigningKey = "至少32字节的签名密钥..............";
}).AddInMemoryStore();

var app = builder.Build();
app.UseCyaimAuthentication();

app.MapGet("/users", () => ...).RequirePermission("sys.user.read");
app.MapGet("/ping", () => "pong").AllowGuest();

app.Run();
```

权限语义：`.`/`:` 分层、大小写不敏感、`*` 匹配一段、`**` 匹配任意后代、**拒绝优先**。

更多场景（独立授权服务器、SSO、WPF/WASM 客户端、WebSocket、ABAC 策略）见 **[docs/getting-started.md](docs/getting-started.md)**。

## 示例

| 示例 | 说明 |
|---|---|
| [samples/Sample.AuthServer](samples/Sample.AuthServer) | 授权服务器 + SSO + 管理面板 |
| [samples/Sample.WebApi](samples/Sample.WebApi) | 资源 API：Minimal API / 控制器 / WebSocket 三种形态 + 拒绝优先演示 |
| [samples/Sample.Wpf](samples/Sample.Wpf) | WPF 桌面客户端：登录、令牌缓存、按权限启停按钮 |
| [samples/Sample.Wasm](samples/Sample.Wasm) | Blazor WebAssembly：授权码 + PKCE |
| [samples/Sample.Cluster](samples/Sample.Cluster) | 多实例集群：共享数据库 + 跨实例缓存失效（无 Redis） |

## 文档

📖 **[文档中心](docs/README.md)** —— 统一入口，含按角色的阅读路径与完整目录。所有文档从这里索引，不散落。

常用直达：
- [快速上手](docs/getting-started.md) · [架构总览](docs/concepts/architecture.md) · [权限模型](docs/concepts/permission-model.md)
- 指南：[保护 API](docs/guides/protect-aspnetcore.md) · [授权中心与 SSO](docs/guides/auth-server-sso.md) · [管理面板](docs/guides/admin-panel.md) · [客户端](docs/guides/desktop-wasm-clients.md) · [生产清单](docs/guides/production-checklist.md)
- 参考：[配置](docs/reference/configuration.md) · [API](docs/reference/api.md) · [服务器端点](docs/reference/server-endpoints.md) · [管理 API](docs/reference/admin-api.md) · [权限代码](docs/reference/permission-codes.md)
- [标准对齐](docs/standards-alignment.md) · [对标 IdentityServer](docs/id5-parity.md) · [从 1.x 迁移](docs/migration-1x.md) · [性能基准](docs/benchmark-results.md) · [交付验证报告](VERIFICATION.md)
- LLM / 工具索引：[llms.txt](llms.txt)

## 1.x 兼容

1.x 的 `ConfigureAuth` / `UseAuth` / `[AuthEndPoint]` 全部保留并标记 `[Obsolete]`，可平滑升级，见[迁移指南](docs/migration-1x.md)。

## License

MIT
