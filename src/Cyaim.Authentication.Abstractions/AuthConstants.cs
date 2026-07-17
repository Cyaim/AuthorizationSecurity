using System;

namespace Cyaim.Authentication.Abstractions
{
    /// <summary>
    /// 框架级常量：声明类型、授权类型、默认端点路径等。
    /// </summary>
    public static class AuthConstants
    {
        /// <summary>认证方案名称</summary>
        public const string SchemeName = "CyaimAuth";

        /// <summary>匹配所有权限的通配符代码</summary>
        public const string AllPermissions = "**";

        /// <summary>游客主体Id</summary>
        public const string GuestSubjectId = "sys_guest";

        /// <summary>
        /// 标准声明类型（对齐 OIDC / JWT 注册声明）。
        /// </summary>
        public static class ClaimTypes
        {
            /// <summary>主体标识 (RFC 7519 sub)</summary>
            public const string Subject = "sub";
            /// <summary>用户名 (OIDC preferred_username)</summary>
            public const string PreferredUserName = "preferred_username";
            /// <summary>显示名 (OIDC name)</summary>
            public const string Name = "name";
            /// <summary>角色</summary>
            public const string Role = "role";
            /// <summary>权限代码（框架私有声明）</summary>
            public const string Permission = "perm";
            /// <summary>作用域 (RFC 8693 scope)</summary>
            public const string Scope = "scope";
            /// <summary>客户端标识 (RFC 8693 client_id)</summary>
            public const string ClientId = "client_id";
            /// <summary>会话标识 (OIDC sid)</summary>
            public const string SessionId = "sid";
            /// <summary>签发者 (RFC 7519 iss)</summary>
            public const string Issuer = "iss";
            /// <summary>受众 (RFC 7519 aud)</summary>
            public const string Audience = "aud";
            /// <summary>JWT唯一标识 (RFC 7519 jti)</summary>
            public const string TokenId = "jti";
            /// <summary>认证时间 (OIDC auth_time)</summary>
            public const string AuthTime = "auth_time";
            /// <summary>邮箱 (OIDC email)</summary>
            public const string Email = "email";
            /// <summary>安全戳（框架私有声明，用户凭据变更后使旧令牌失效）</summary>
            public const string SecurityStamp = "sstamp";
        }

        /// <summary>
        /// OAuth 2.0 授权类型 (RFC 6749)。
        /// </summary>
        public static class GrantTypes
        {
            /// <summary>授权码模式</summary>
            public const string AuthorizationCode = "authorization_code";
            /// <summary>客户端凭据模式</summary>
            public const string ClientCredentials = "client_credentials";
            /// <summary>资源所有者密码模式</summary>
            public const string Password = "password";
            /// <summary>刷新令牌</summary>
            public const string RefreshToken = "refresh_token";
        }

        /// <summary>
        /// 标准作用域 (OIDC)。
        /// </summary>
        public static class Scopes
        {
            /// <summary>OIDC 身份作用域</summary>
            public const string OpenId = "openid";
            /// <summary>基础资料</summary>
            public const string Profile = "profile";
            /// <summary>离线访问（签发刷新令牌）</summary>
            public const string OfflineAccess = "offline_access";
            /// <summary>权限作用域（令牌携带 perm 声明）</summary>
            public const string Permissions = "permissions";
        }

        /// <summary>
        /// 默认端点路径（对齐 OIDC Discovery / IdentityServer 布局）。
        /// </summary>
        public static class Endpoints
        {
            /// <summary>发现文档</summary>
            public const string Discovery = "/.well-known/openid-configuration";
            /// <summary>JWKS 公钥集</summary>
            public const string Jwks = "/.well-known/jwks";
            /// <summary>令牌端点</summary>
            public const string Token = "/connect/token";
            /// <summary>授权端点</summary>
            public const string Authorize = "/connect/authorize";
            /// <summary>令牌自省 (RFC 7662)</summary>
            public const string Introspect = "/connect/introspect";
            /// <summary>令牌吊销 (RFC 7009)</summary>
            public const string Revoke = "/connect/revocation";
            /// <summary>用户信息 (OIDC UserInfo)</summary>
            public const string UserInfo = "/connect/userinfo";
            /// <summary>结束会话（单点登出）</summary>
            public const string EndSession = "/connect/endsession";
            /// <summary>登录页</summary>
            public const string Login = "/account/login";
            /// <summary>登出页</summary>
            public const string Logout = "/account/logout";
            /// <summary>管理面板</summary>
            public const string AdminPanel = "/auth-admin";
        }

        /// <summary>
        /// 内置管理权限代码。
        /// </summary>
        public static class AdminPermissions
        {
            /// <summary>管理面板全部权限</summary>
            public const string All = "auth.admin.**";
            /// <summary>查看</summary>
            public const string Read = "auth.admin.read";
            /// <summary>用户管理</summary>
            public const string ManageUsers = "auth.admin.users";
            /// <summary>角色管理</summary>
            public const string ManageRoles = "auth.admin.roles";
            /// <summary>权限管理</summary>
            public const string ManagePermissions = "auth.admin.permissions";
            /// <summary>客户端管理</summary>
            public const string ManageClients = "auth.admin.clients";
            /// <summary>审计日志查看</summary>
            public const string ReadAudit = "auth.admin.audit";
        }
    }
}
