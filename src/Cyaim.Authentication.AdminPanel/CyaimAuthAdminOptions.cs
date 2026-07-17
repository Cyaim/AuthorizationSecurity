using Cyaim.Authentication.Abstractions;

namespace Cyaim.Authentication.AdminPanel
{
    /// <summary>
    /// 管理面板配置。
    /// </summary>
    public class CyaimAuthAdminOptions
    {
        /// <summary>面板挂载路径（SPA 与管理 API 的公共前缀），默认 /auth-admin</summary>
        public string BasePath { get; set; } = AuthConstants.Endpoints.AdminPanel;

        /// <summary>
        /// SPA 登录使用的令牌端点（OAuth 2.0 password 模式），默认 /connect/token；
        /// 可配置为其他授权服务器的绝对地址。
        /// </summary>
        public string TokenEndpoint { get; set; } = AuthConstants.Endpoints.Token;

        /// <summary>SPA 登录使用的客户端Id，默认 cyaim-admin-panel</summary>
        public string ClientId { get; set; } = "cyaim-admin-panel";

        /// <summary>服务器显示名称（登录页与侧边栏标题），为空时 SPA 使用默认名称</summary>
        public string? ServerName { get; set; }
    }
}
