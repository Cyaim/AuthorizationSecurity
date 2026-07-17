# Sample.Wpf — WPF 桌面客户端示例

演示 `Cyaim.Authentication.Client` SDK 在桌面场景的用法：

- 统一登录（密码模式 `grant_type=password`，公共客户端 `wpf-client`，无密钥）
- 令牌缓存持久化：`FileTokenCache` 写入 `%LOCALAPPDATA%\CyaimSample\token.json`，用 Windows DPAPI（`ProtectedData`，当前用户范围）加密——重启应用免登录
- 自动刷新：访问令牌过期自动用刷新令牌续期（scope 含 `offline_access`）
- UI 权限门控：`LoadPermissionsAsync()` 后用 `HasPermission("demo.order.read|create|delete")` 启停按钮，禁用原因写在 ToolTip
- 调用资源 API：`CyaimAuthHttpMessageHandler` 自动附加 `Authorization: Bearer`，收到 401 时刷新一次并重试
- `TokenChanged` / `SessionExpired` 事件回 UI 线程；会话过期弹窗提示并回登录窗

## 运行步骤

三个进程按顺序启动（各开一个终端，均在仓库根目录执行）：

1. **授权中心**（登录、发令牌）

   ```powershell
   dotnet run --project samples/Sample.AuthServer --urls http://127.0.0.1:5299
   ```

   不加 `--urls` 时端口动态分配，需记下控制台打印的实际地址并在登录窗的「服务器」栏填入。

2. **资源 API**（受权限保护的 `/api/orders`）

   ```powershell
   dotnet run --project samples/Sample.WebApi --urls http://127.0.0.1:5298
   ```

3. **本示例**

   ```powershell
   dotnet run --project samples/Sample.Wpf
   ```

登录后点「GET /api/orders」调用资源 API；用不同账户登录可观察三个订单按钮的启停差异。点「注销」吊销刷新令牌、删除本地缓存并回到登录窗。

## 演示账户

| 用户名 | 密码 | 角色 | demo.order.read | demo.order.create | demo.order.delete |
| ------ | ---- | ---- | :-: | :-: | :-: |
| admin | Admin!123 | admin（`demo.**` 全通配） | ✅ | ✅ | ✅ |
| alice | alice123 | order-admin（`demo.order.**`） | ✅ | ✅ | ✅ |
| bob | bob123 | order-viewer（仅 `demo.order.read`） | ✅ | ❌ | ❌ |

> 账户与 `wpf-client` 客户端由 Sample.AuthServer 启动时幂等种子；删除 `samples/Sample.AuthServer/data/auth-store.json` 可重置数据。

## 免登录恢复

登录成功后令牌被加密缓存。下次启动时若缓存令牌有效（或可刷新），应用直接进入主窗口；令牌失效或服务器不可达则回到登录窗。缓存文件仅当前 Windows 用户可解密。
