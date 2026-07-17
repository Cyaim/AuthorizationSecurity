using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;
using Cyaim.Authentication.Core.Audit;
using Cyaim.Authentication.Tests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Cyaim.Authentication.Tests
{
    /// <summary>
    /// <see cref="DefaultAuditLogger"/> 测试：查询过滤、倒序、容量、文件落盘。
    /// </summary>
    public class DefaultAuditLoggerTests
    {
        private static DefaultAuditLogger Create(Action<CyaimAuthCoreOptions>? configure = null)
        {
            var options = new CyaimAuthCoreOptions();
            configure?.Invoke(options);
            return new DefaultAuditLogger(Options.Create(options), NullLogger<DefaultAuditLogger>.Instance);
        }

        private static AuditEvent Event(
            string id,
            AuditCategory category = AuditCategory.Login,
            AuditOutcome outcome = AuditOutcome.Success,
            string? subjectId = null,
            DateTimeOffset? timestamp = null) => new AuditEvent
            {
                Id = id,
                Category = category,
                Outcome = outcome,
                SubjectId = subjectId,
                Timestamp = timestamp ?? new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            };

        [Fact]
        public async Task 查询_按类别与结果过滤()
        {
            using DefaultAuditLogger logger = Create();
            await logger.WriteAsync(Event("e1", AuditCategory.Login, AuditOutcome.Success));
            await logger.WriteAsync(Event("e2", AuditCategory.Login, AuditOutcome.Denied));
            await logger.WriteAsync(Event("e3", AuditCategory.Admin, AuditOutcome.Success));

            IReadOnlyList<AuditEvent> logins = await logger.QueryAsync(new AuditQuery { Category = AuditCategory.Login });
            Assert.Equal(2, logins.Count);
            Assert.All(logins, x => Assert.Equal(AuditCategory.Login, x.Category));

            IReadOnlyList<AuditEvent> denied = await logger.QueryAsync(new AuditQuery { Outcome = AuditOutcome.Denied });
            Assert.Single(denied);
            Assert.Equal("e2", denied[0].Id);

            IReadOnlyList<AuditEvent> combined = await logger.QueryAsync(new AuditQuery
            {
                Category = AuditCategory.Login,
                Outcome = AuditOutcome.Success,
            });
            Assert.Single(combined);
            Assert.Equal("e1", combined[0].Id);
        }

        [Fact]
        public async Task 查询_按主体过滤()
        {
            using DefaultAuditLogger logger = Create();
            await logger.WriteAsync(Event("e1", subjectId: "u1"));
            await logger.WriteAsync(Event("e2", subjectId: "u2"));
            await logger.WriteAsync(Event("e3", subjectId: "u1"));

            IReadOnlyList<AuditEvent> result = await logger.QueryAsync(new AuditQuery { SubjectId = "u1" });

            Assert.Equal(2, result.Count);
            Assert.All(result, x => Assert.Equal("u1", x.SubjectId));
        }

        [Fact]
        public async Task 查询_按时间范围过滤()
        {
            using DefaultAuditLogger logger = Create();
            var t0 = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
            await logger.WriteAsync(Event("e1", timestamp: t0));
            await logger.WriteAsync(Event("e2", timestamp: t0.AddHours(1)));
            await logger.WriteAsync(Event("e3", timestamp: t0.AddHours(2)));

            IReadOnlyList<AuditEvent> result = await logger.QueryAsync(new AuditQuery
            {
                From = t0.AddMinutes(30),
                To = t0.AddMinutes(90),
            });

            Assert.Single(result);
            Assert.Equal("e2", result[0].Id);
        }

        [Fact]
        public async Task 查询_按写入顺序倒序返回()
        {
            using DefaultAuditLogger logger = Create();
            await logger.WriteAsync(Event("e1"));
            await logger.WriteAsync(Event("e2"));
            await logger.WriteAsync(Event("e3"));

            IReadOnlyList<AuditEvent> result = await logger.QueryAsync(new AuditQuery());

            Assert.Equal(new[] { "e3", "e2", "e1" }, result.Select(x => x.Id));
        }

        [Fact]
        public async Task 查询_分页()
        {
            using DefaultAuditLogger logger = Create();
            for (int i = 1; i <= 5; i++)
            {
                await logger.WriteAsync(Event($"e{i}"));
            }

            IReadOnlyList<AuditEvent> page = await logger.QueryAsync(new AuditQuery { Skip = 1, Take = 2 });

            Assert.Equal(new[] { "e4", "e3" }, page.Select(x => x.Id));
        }

        [Fact]
        public async Task 容量裁剪_超出后丢弃最旧()
        {
            using DefaultAuditLogger logger = Create(o => o.AuditCapacity = 5);
            for (int i = 1; i <= 10; i++)
            {
                await logger.WriteAsync(Event($"e{i}"));
            }

            IReadOnlyList<AuditEvent> all = await logger.QueryAsync(new AuditQuery { Take = 100 });

            Assert.Equal(5, all.Count);
            Assert.Equal("e10", all[0].Id);   // 最新的保留
            Assert.DoesNotContain(all, x => x.Id == "e1"); // 最旧的被丢弃
        }

        [Fact]
        public async Task JSONL文件落盘_行数与内容正确()
        {
            using var dir = new TempDir();
            string path = dir.File("audit.jsonl");
            using DefaultAuditLogger logger = Create(o => o.AuditFilePath = path);

            await logger.WriteAsync(Event("e1"));
            await logger.WriteAsync(Event("e2", AuditCategory.Security, AuditOutcome.Failure));
            await logger.WriteAsync(Event("e3"));

            Assert.True(File.Exists(path));
            string[] lines = File.ReadAllLines(path);
            Assert.Equal(3, lines.Length);

            // 每行都是合法 JSON 且能还原事件Id
            var ids = new List<string?>();
            foreach (string line in lines)
            {
                using JsonDocument doc = JsonDocument.Parse(line);
                ids.Add(doc.RootElement.GetProperty("Id").GetString());
            }
            Assert.Equal(new[] { "e1", "e2", "e3" }, ids);
        }

        [Fact]
        public async Task 写入null事件_安全忽略()
        {
            using DefaultAuditLogger logger = Create();

            await logger.WriteAsync(null!);

            Assert.Empty(await logger.QueryAsync(new AuditQuery()));
        }
    }
}
