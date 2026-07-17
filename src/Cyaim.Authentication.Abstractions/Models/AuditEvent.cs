using System;

namespace Cyaim.Authentication.Abstractions.Models
{
    /// <summary>
    /// 审计事件。
    /// </summary>
    public class AuditEvent
    {
        /// <summary>事件Id</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        /// <summary>发生时间</summary>
        public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>事件类别</summary>
        public AuditCategory Category { get; set; }

        /// <summary>结果</summary>
        public AuditOutcome Outcome { get; set; }

        /// <summary>主体Id</summary>
        public string? SubjectId { get; set; }

        /// <summary>主体名称</summary>
        public string? SubjectName { get; set; }

        /// <summary>客户端Id</summary>
        public string? ClientId { get; set; }

        /// <summary>涉及的资源（端点路径、权限代码、被管理对象Id 等）</summary>
        public string? Resource { get; set; }

        /// <summary>动作描述</summary>
        public string? Action { get; set; }

        /// <summary>详情</summary>
        public string? Detail { get; set; }

        /// <summary>来源IP</summary>
        public string? RemoteIp { get; set; }
    }

    /// <summary>审计事件类别</summary>
    public enum AuditCategory
    {
        /// <summary>登录</summary>
        Login = 0,
        /// <summary>登出</summary>
        Logout = 1,
        /// <summary>令牌签发</summary>
        TokenIssued = 2,
        /// <summary>令牌吊销</summary>
        TokenRevoked = 3,
        /// <summary>权限判断</summary>
        PermissionCheck = 4,
        /// <summary>管理操作（用户/角色/权限/客户端变更）</summary>
        Admin = 5,
        /// <summary>安全事件（重放、锁定、可疑行为）</summary>
        Security = 6,
    }

    /// <summary>审计结果</summary>
    public enum AuditOutcome
    {
        /// <summary>成功</summary>
        Success = 0,
        /// <summary>被拒绝</summary>
        Denied = 1,
        /// <summary>失败（错误）</summary>
        Failure = 2,
    }
}
