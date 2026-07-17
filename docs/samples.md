# 示例总览

> 仓库 `samples/` 下四个可运行示例的用途、启动命令、端口与演示账户，以及从零跑通「授权中心 → 资源 API → 客户端」的完整步骤。

`[文档中心](README.md) / 示例`

所有示例目标框架 `net9.0`（WPF 为 `net9.0-windows`，仅 Windows），需 .NET SDK 9。示例源码位于仓库 `samples/` 目录。

---

## 四个示例一览

| 示例 | 路径 | 说明 | 启动命令 | 端口 |
| --- | --- | --- | --- | --- |
| 授权中心 | `samples/Sample.AuthServer` | OAuth2/OIDC 端点 + 统一登录（SSO）+ 内嵌权限管理面板；数据落 `data/auth-store.json` | `dotnet run --project samples/Sample.AuthServer --urls http://127.0.0.1:5299` | 5299 |
| 资源 API | `samples/Sample.WebApi` | 受权限保护的订单 API（Minimal API / 控制器 / WebSocket 三种形态） | `dotnet run --project samples/Sample.WebApi --urls http://127.0.0.1:5298` | 5298 |
| WPF 桌面 | `samples/Sample.Wpf` | 密码模式登录 + DPAPI 令牌缓存 + 本地权限门控（仅 Windows） | `dotnet run --project samples/Sample.Wpf` | 桌面应用 |
| Blazor WASM | `samples/Sample.Wasm` | 浏览器授权码 + PKCE 统一登录 | `dotnet run --project samples/Sample.Wasm` | 5290（固定） |
| 集群 | `samples/Sample.Cluster` | 多实例共享数据库 + 跨实例缓存失效（无 Redis） | `CYAIM_DB=./c.db dotnet run --project samples/Sample.Cluster --urls http://127.0.0.1:5401`（起两个指向同一 DB） | 自定 |

> **端口不是随意的**：授权中心种子里 `wasm-client` 的回调地址是 `http://localhost:5290/callback`，WASM 应用端口已在 `launchSettings.json` 固定为 5290；WPF 与 WASM 默认连的授权中心是 `http://127.0.0.1:5299`、资源 API 是 `http://127.0.0.1:5298`。启动前两个服务时请按上表 `--urls` 指定端口，否则需相应改动客户端配置。

---

## 完整跑通步骤

开三个终端，均在仓库根目录执行，**按顺序启动**：

### 1. 先起授权中心（5299）

```bash
dotnet run --project samples/Sample.AuthServer --urls http://127.0.0.1:5299
```

启动时幂等种子用户、角色、客户端、权限定义到 `samples/Sample.AuthServer/data/auth-store.json`（删除该文件即重置数据）。可访问：

- 权限管理面板 `http://127.0.0.1:5299/auth-admin`（用 `admin / Admin!123` 登录，见 [使用权限管理面板](guides/admin-panel.md)）
- OIDC 发现文档 `http://127.0.0.1:5299/.well-known/openid-configuration`
- 统一登录页 `http://127.0.0.1:5299/account/login`

### 2. 再起资源 API（5298）

```bash
dotnet run --project samples/Sample.WebApi --urls http://127.0.0.1:5298
```

资源 API 与授权中心共享同一 HMAC 签名密钥（示例中 `demo-shared-signing-key-32bytes!!`），因此能校验授权中心签发的令牌。它另有一套内存种子用户，并在启动时把演示令牌打印到控制台，便于 `curl` / `wscat` 直接测试。受保护端点：

- `GET /api/orders` —— 需 `demo.order.read`
- `POST /api/orders` —— 需 `demo.order.create`
- `DELETE /api/orders/{index}` —— 需 `demo.order.delete`
- `GET /api/profile` —— 仅需已认证
- `GET /api/policy-demo` —— 需 `demo.order.read` + `even-minute` ABAC 策略
- `GET /ws/echo` —— WebSocket，需 `demo.ws.connect`（广播指令另需 `demo.ws.broadcast`），见 [WebSocket 鉴权](guides/websocket.md)

### 3. 最后起客户端

**WPF 桌面**（仅 Windows）：

```bash
dotnet run --project samples/Sample.Wpf
```

登录后点「GET /api/orders」调用资源 API；用不同账户登录可观察三个订单按钮的启停差异；点「注销」吊销刷新令牌、删除本地 DPAPI 缓存并回登录窗。令牌加密缓存于 `%LOCALAPPDATA%\CyaimSample\token.json`，下次启动若仍有效则免登录直接进主窗口。

**Blazor WASM**（浏览器）：

```bash
dotnet run --project samples/Sample.Wasm
```

浏览器访问 `http://localhost:5290`，点「登录」跳到授权中心完成密码认证后回跳，加载权限并按 `demo.order.read` 启停「读取订单」按钮。

> WASM 在浏览器中跨域调用 `/connect/token`、`/connect/userinfo` 与资源 API，受同源策略限制。完整体验需在 `Sample.AuthServer` 与 `Sample.WebApi` 中开启 CORS 允许来源 `http://localhost:5290`——详见 `samples/Sample.Wasm/README.md` 的 CORS 说明。

---

## 演示账户

授权中心（`Sample.AuthServer`）种子用户，供 WPF / WASM 客户端与管理面板登录：

| 用户名 | 密码 | 角色 | 授予权限 | demo.order.read | demo.order.create | demo.order.delete |
| --- | --- | --- | --- | :-: | :-: | :-: |
| `admin` | `Admin!123` | admin | `auth.admin.**` + `demo.**`（全通配） | ✅ | ✅ | ✅ |
| `alice` | `alice123` | order-admin | `demo.order.**`、`demo.ws.**`（继承 order-viewer） | ✅ | ✅ | ✅ |
| `bob` | `bob123` | order-viewer | 仅 `demo.order.read` | ✅ | ❌ | ❌ |

授权中心种子客户端：

| client_id | 密钥 | 授权类型 | 用途 |
| --- | --- | --- | --- |
| `cyaim-admin-panel` | 无（公共） | password, refresh_token | 权限管理面板 SPA |
| `wpf-client` | 无（公共） | password, refresh_token | WPF 桌面示例 |
| `wasm-client` | 无（公共） | authorization_code, refresh_token（PKCE 必需） | Blazor WASM 示例，回调 `http://localhost:5290/callback` |
| `demo-m2m` | `m2m-secret-please-change` | client_credentials | 服务间调用（预置 `demo.order.read` 权限） |

> 资源 API（`Sample.WebApi`）另有一套独立内存种子用户：`alice/alice123`（order-admin）、`bob/bob123`（order-viewer）、`carol/carol123`（order-admin-restricted，被显式拒绝 `demo.order.delete`，演示拒绝优先）。这套账户仅用于该服务自签的演示令牌，客户端示例统一走授权中心认证。

---

## 相关文档

- [桌面/WASM/控制台客户端](guides/desktop-wasm-clients.md) —— WPF、WASM、控制台的 Client SDK 用法
- [搭建授权中心与统一登录](guides/auth-server-sso.md) —— `Sample.AuthServer` 背后的配置
- [保护 ASP.NET Core API](guides/protect-aspnetcore.md) —— `Sample.WebApi` 背后的权限校验
- [使用权限管理面板](guides/admin-panel.md) —— `/auth-admin` 面板功能
- [WebSocket 鉴权](guides/websocket.md) —— `/ws/echo` 的握手与消息级权限
- [快速上手](getting-started.md)
</content>
