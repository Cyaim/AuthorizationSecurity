# 对标 IdentityServer（Duende / ID5）功能矩阵

> 面包屑：[文档中心](README.md) / 标准与对标

以 Duende IdentityServer 的核心能力清单为参照，标注 Cyaim.Authentication 2.0 的覆盖情况。

图例：✅ 已实现 ｜ 🟡 部分实现/有替代方案 ｜ ❌ 未实现（规划中）

## 协议端点

| 能力 | ID5 | Cyaim 2.0 | 说明 |
|---|---|---|---|
| Discovery（/.well-known/openid-configuration） | ✅ | ✅ | |
| JWKS 公钥端点 | ✅ | ✅ | RS256；HS256 时返回空 keys |
| 令牌端点（authorization_code） | ✅ | ✅ | 含 PKCE S256 强制选项 |
| 令牌端点（client_credentials） | ✅ | ✅ | 客户端可直接绑定权限代码 |
| 令牌端点（refresh_token） | ✅ | ✅ | 一次性轮换 + 重放检测吊销家族 |
| 令牌端点（password） | ✅（弃用） | ✅（可关闭） | 供桌面/受信客户端；默认开启可配置关闭 |
| 授权端点 + 登录重定向 | ✅ | ✅ | 内嵌登录页，SSO 会话 Cookie |
| 令牌自省（RFC 7662） | ✅ | ✅ | 访问令牌 + 刷新令牌 |
| 令牌吊销（RFC 7009） | ✅ | ✅ | |
| UserInfo | ✅ | ✅ | 额外返回有效权限列表 |
| 结束会话/登出 | ✅ | ✅ | post_logout_redirect_uri 校验 |
| 设备授权流（RFC 8628） | ✅ | ❌ | 规划 |
| CIBA | ✅ | ❌ | 不在目标内 |
| 动态客户端注册 | 🟡 | 🟡 | 通过管理面板/管理 API 注册 |

## 令牌与密钥

| 能力 | ID5 | Cyaim 2.0 | 说明 |
|---|---|---|---|
| JWT 访问令牌 | ✅ | ✅ | RS256 / HS256 |
| 引用令牌（reference token） | ✅ | 🟡 | 刷新令牌为引用型；访问令牌自包含 + 自省可用 |
| 自动密钥管理 | ✅ | ✅ | RSA 密钥自动生成并持久化，kid 稳定 |
| 密钥轮换 | ✅ | ❌ | 规划：多密钥 JWKS |
| 刷新令牌轮换/重放防护 | ✅ | ✅ | RFC 9700 §4.14 语义 |
| 自定义声明 | ✅ | ✅ | `AccessTokenRequest.ExtraClaims` / 用户 Claims |

## 客户端与配置

| 能力 | ID5 | Cyaim 2.0 | 说明 |
|---|---|---|---|
| 客户端注册（grants/scopes/redirect/lifetimes/CORS） | ✅ | ✅ | `ClientApplication` |
| 客户端密钥哈希存储 | ✅ | ✅ | PBKDF2 |
| Scope 校验 | ✅ | ✅ | |
| 每客户端令牌有效期 | ✅ | ✅ | |
| 存储抽象（EF/自定义） | ✅ | 🟡 | 6 个存储接口；内置 InMemory/JSON 文件。自定义存储经 `MapStore<T>` 以**单例**注册——EF/DbContext 实现须在存储内部用 `IDbContextFactory`/`IServiceScopeFactory` 自建作用域，不能直接持有 Scoped `DbContext` |
| CORS（浏览器客户端跨源） | ✅ | 🟡 | `ClientApplication.AllowedCorsOrigins` 记录声明，但框架不自动下发 CORS 头；宿主用 ASP.NET Core `UseCors` 配置（可读取该字段） |

## 授权模型（ID5 本体不含，Cyaim 内置）

| 能力 | ID5 | Cyaim 2.0 | 说明 |
|---|---|---|---|
| RBAC 角色层级 | ❌（需搭配外部方案） | ✅ | NIST RBAC1 |
| 细粒度权限代码 + 通配符 | ❌ | ✅ | Shiro 风格，编译权限集 O(1) 判断 |
| 拒绝优先授权 | ❌ | ✅ | |
| ABAC 命名策略 | ❌ | ✅ | |
| 端点权限中间件（含 WebSocket） | ❌ | ✅ | |
| 管理面板（用户/角色/权限/客户端/审计） | 🟡（商业 AdminUI） | ✅ | 内嵌 SPA，免费 |
| 审计日志 | 🟡 | ✅ | |
| 客户端 SDK（桌面/WASM） | ❌ | ✅ | 自动刷新 + 本地权限判断 |

## 用户体系

| 能力 | ID5 | Cyaim 2.0 | 说明 |
|---|---|---|---|
| 用户存储 | 🟡（外接 Identity） | ✅ 内置 | `IUserStore` + 锁定策略 |
| 口令哈希 | 外接 | ✅ | PBKDF2-HMAC-SHA256 |
| 外部身份提供方（Google/AD 等联合登录） | ✅ | ❌ | 规划：外部 IdP 桥接 |
| MFA | 外接 | ❌ | 规划 |

## 总结

ID5 核心协议面（端点、令牌、客户端模型、SSO）已覆盖其主干能力；设备流、CIBA、密钥轮换、外部 IdP、MFA 为已知差距（见上表 ❌ 项）。Cyaim 2.0 同时内置了 ID5 本体不提供的授权引擎（RBAC/ABAC/权限码）、管理面板与客户端 SDK。
