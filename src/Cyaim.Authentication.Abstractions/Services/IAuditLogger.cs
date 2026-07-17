using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;

namespace Cyaim.Authentication.Abstractions.Services
{
    /// <summary>
    /// 审计日志服务。
    /// </summary>
    public interface IAuditLogger
    {
        /// <summary>
        /// 写入审计事件。实现不应抛出异常阻断业务流程。
        /// </summary>
        Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

        /// <summary>
        /// 查询审计事件（按时间倒序）。
        /// </summary>
        Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// 审计查询条件。
    /// </summary>
    public class AuditQuery
    {
        /// <summary>起始时间</summary>
        public DateTimeOffset? From { get; set; }

        /// <summary>截止时间</summary>
        public DateTimeOffset? To { get; set; }

        /// <summary>类别过滤</summary>
        public AuditCategory? Category { get; set; }

        /// <summary>结果过滤</summary>
        public AuditOutcome? Outcome { get; set; }

        /// <summary>主体过滤</summary>
        public string? SubjectId { get; set; }

        /// <summary>跳过条数</summary>
        public int Skip { get; set; }

        /// <summary>返回条数（默认100，上限1000）</summary>
        public int Take { get; set; } = 100;
    }
}
