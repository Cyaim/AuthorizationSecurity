using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cyaim.Authentication.Core.Audit
{
    /// <summary>
    /// 默认审计日志：内存环形缓冲（可查询）+ 可选 JSONL 文件落盘 + ILogger 结构化输出。
    /// 写入永不抛出异常，不阻断业务流程。
    /// </summary>
    public sealed class DefaultAuditLogger : IAuditLogger, IDisposable
    {
        private readonly ConcurrentQueue<AuditEvent> _buffer = new ConcurrentQueue<AuditEvent>();
        private readonly SemaphoreSlim _fileLock = new SemaphoreSlim(1, 1);
        private readonly CyaimAuthCoreOptions _options;
        private readonly ILogger<DefaultAuditLogger> _logger;

        /// <summary>创建审计日志服务</summary>
        public DefaultAuditLogger(IOptions<CyaimAuthCoreOptions> options, ILogger<DefaultAuditLogger> logger)
        {
            _options = options.Value;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task WriteAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            if (auditEvent == null)
            {
                return;
            }

            try
            {
                _buffer.Enqueue(auditEvent);
                while (_buffer.Count > _options.AuditCapacity && _buffer.TryDequeue(out _))
                {
                }

                _logger.LogInformation(
                    "审计 {Category}/{Outcome} subject={SubjectId} client={ClientId} resource={Resource} action={Action} detail={Detail}",
                    auditEvent.Category, auditEvent.Outcome, auditEvent.SubjectId, auditEvent.ClientId,
                    auditEvent.Resource, auditEvent.Action, auditEvent.Detail);

                if (!string.IsNullOrEmpty(_options.AuditFilePath))
                {
                    await AppendToFileAsync(auditEvent, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "审计事件写入失败");
            }
        }

        /// <inheritdoc/>
        public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default)
        {
            query ??= new AuditQuery();
            int take = Math.Min(Math.Max(1, query.Take), 1000);

            IEnumerable<AuditEvent> events = _buffer.ToArray().Reverse();

            if (query.From.HasValue)
            {
                events = events.Where(x => x.Timestamp >= query.From.Value);
            }
            if (query.To.HasValue)
            {
                events = events.Where(x => x.Timestamp <= query.To.Value);
            }
            if (query.Category.HasValue)
            {
                events = events.Where(x => x.Category == query.Category.Value);
            }
            if (query.Outcome.HasValue)
            {
                events = events.Where(x => x.Outcome == query.Outcome.Value);
            }
            if (!string.IsNullOrEmpty(query.SubjectId))
            {
                events = events.Where(x => string.Equals(x.SubjectId, query.SubjectId, StringComparison.Ordinal));
            }

            IReadOnlyList<AuditEvent> result = events.Skip(query.Skip).Take(take).ToArray();
            return Task.FromResult(result);
        }

        private async Task AppendToFileAsync(AuditEvent auditEvent, CancellationToken cancellationToken)
        {
            string line = JsonSerializer.Serialize(auditEvent) + Environment.NewLine;
            byte[] bytes = Encoding.UTF8.GetBytes(line);

            await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                string path = _options.AuditFilePath!;
                string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                using FileStream stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, useAsync: true);
                await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _fileLock.Dispose();
        }
    }
}
