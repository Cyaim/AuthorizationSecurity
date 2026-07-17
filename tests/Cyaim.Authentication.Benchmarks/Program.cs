using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Microsoft.Extensions.DependencyInjection;

namespace Cyaim.Authentication.Benchmarks
{
    /// <summary>
    /// Cyaim.Authentication 2.0 性能基准入口。
    /// 自研 harness（预热 2 轮 + 正式 5 轮取中位数），输出控制台 markdown 表格并写入 docs/benchmark-results.md。
    /// </summary>
    public static class Program
    {
        private const long StandardIterations = 1_000_000;
        private const int QueryMask = 4095; // 预生成查询数组大小 4096

        /// <summary>
        /// 程序入口。
        /// </summary>
        public static async Task<int> Main()
        {
            var report = new StringBuilder();
            report.AppendLine("# Cyaim.Authentication 2.0 性能基准报告");
            report.AppendLine();
            report.AppendLine($"- 时间：{DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)}");
            report.AppendLine($"- 运行时：{RuntimeInformation.FrameworkDescription}（{RuntimeInformation.ProcessArchitecture}）");
            report.AppendLine($"- 操作系统：{Environment.OSVersion}");
            report.AppendLine($"- 逻辑处理器：{Environment.ProcessorCount}");
            report.AppendLine($"- Server GC：{GCSettings.IsServerGC}");
            report.AppendLine($"- 测量方式：Stopwatch，预热 2 轮 + 正式 5 轮取中位数");
            report.AppendLine();

            RunScenarioLegacyComparison(report);
            RunScenarioMicroBenchmarks(report);
            RunScenarioBuildCost(report);
            await RunScenarioEndToEndAsync(report);

            report.AppendLine("---");
            report.AppendLine();
            report.AppendLine($"_JIT 黑洞校验值（无实际意义）：{BenchHarness.Sink}_");

            string markdown = report.ToString();
            Console.WriteLine();
            Console.WriteLine(markdown);

            string outputPath = Path.Combine(FindRepoRoot(), "docs", "benchmark-results.md");
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            File.WriteAllText(outputPath, markdown, new UTF8Encoding(false));
            Console.WriteLine($"结果已写入：{outputPath}");
            return 0;
        }

        #region 场景 A：Legacy 1.x 对比

        private static void RunScenarioLegacyComparison(StringBuilder report)
        {
            Console.WriteLine("[1/4] Legacy 1.x LINQ 查找 vs CompiledPermissionSet ...");
            report.AppendLine("## 场景 A：1.x 端点查找 vs 2.0 CompiledPermissionSet");
            report.AppendLine();
            report.AppendLine("模拟旧版 `AuthenticationService.CheckAuth` 的查找形态（LINQ `Where` + `FirstOrDefault` + `ToLower`/`ToUpper` 字符串比较），");
            report.AppendLine("对比新版 `CompiledPermissionSet.IsGranted(PermissionQuery)`。命中分布：50% 命中 / 50% 未命中。");
            report.AppendLine("新版每轮 100 万次查询；旧版按 N 自动缩减每轮次数（结果按 ns/op 归一化，可直接对比）。");
            report.AppendLine();
            report.AppendLine("| N（端点数） | 旧版 ns/op | 旧版 ops/sec | 新版 ns/op | 新版 ops/sec | 加速比 |");
            report.AppendLine("|---:|---:|---:|---:|---:|---:|");

            var speedups = new List<(int N, double Speedup)>();
            foreach (int n in new[] { 100, 1000, 10000 })
            {
                (BenchResult legacy, BenchResult modern) = RunLegacyComparisonCase(n);
                double speedup = legacy.NsPerOp / modern.NsPerOp;
                speedups.Add((n, speedup));
                report.AppendLine(
                    $"| {n} | {BenchHarness.FormatNs(legacy.NsPerOp)} | {BenchHarness.FormatOps(legacy.OpsPerSecond)} " +
                    $"| {BenchHarness.FormatNs(modern.NsPerOp)} | {BenchHarness.FormatOps(modern.OpsPerSecond)} " +
                    $"| **{speedup.ToString("N0", CultureInfo.InvariantCulture)}x** |");
                Console.WriteLine($"  N={n}: legacy {BenchHarness.FormatNs(legacy.NsPerOp)} ns/op, new {BenchHarness.FormatNs(modern.NsPerOp)} ns/op, speedup {speedup:N0}x");
            }

            report.AppendLine();
            report.AppendLine("**结论**：旧版查找为 O(N) 线性扫描且每次比较分配字符串，耗时随端点数线性增长；" +
                "新版编译权限集为哈希/Trie 查找，与规模基本无关。" +
                string.Join("；", speedups.ConvertAll(s => $"N={s.N} 时加速约 {s.Speedup.ToString("N0", CultureInfo.InvariantCulture)} 倍")) + "。");
            report.AppendLine();
        }

        private static (BenchResult Legacy, BenchResult Modern) RunLegacyComparisonCase(int endpointCount)
        {
            var random = new Random(42);

            // 端点集：Ctrl{c}Controller / Act{a}，每控制器 10 个操作
            var endpoints = new LegacyAuthEndPoint[endpointCount];
            var allowCodes = new string[endpointCount];
            for (int i = 0; i < endpointCount; i++)
            {
                int c = i / 10;
                int a = i % 10;
                endpoints[i] = new LegacyAuthEndPoint
                {
                    ControllerName = $"Ctrl{c}Controller",
                    ActionName = $"Act{a}",
                    Routes = new[] { new LegacyRouteEntry { HttpMethods = new string?[] { "GET", "POST" }, Template = $"ctrl{c}/act{a}" } },
                    IsAllow = true,
                };
                allowCodes[i] = $"ctrl{c}.act{a}";
            }

            // 预生成 4096 条查询：偶数命中、奇数未命中
            int queryCount = QueryMask + 1;
            var legacyControllers = new string[queryCount];
            var legacyActions = new string[queryCount];
            var modernQueries = new PermissionQuery[queryCount];
            for (int i = 0; i < queryCount; i++)
            {
                int pick = random.Next(endpointCount);
                int c = pick / 10;
                legacyControllers[i] = $"ctrl{c}";
                if ((i & 1) == 0)
                {
                    int a = pick % 10;
                    legacyActions[i] = $"act{a}";
                    modernQueries[i] = PermissionQuery.Parse($"ctrl{c}.act{a}");
                }
                else
                {
                    legacyActions[i] = $"missing{i % 17}";
                    modernQueries[i] = PermissionQuery.Parse($"ctrl{c}.missing{i % 17}");
                }
            }

            // 旧版为 O(N) 扫描，按 N 缩减每轮次数以保证可快速复跑（ns/op 已归一化）
            long legacyIterations = Math.Max(2_000, 20_000_000 / endpointCount);
            BenchResult legacy = BenchHarness.Measure($"legacy N={endpointCount}", legacyIterations, iterations =>
            {
                long hits = 0;
                for (long i = 0; i < iterations; i++)
                {
                    int idx = (int)(i & QueryMask);
                    if (LegacyAuthChecker.CheckAuth(endpoints, legacyControllers[idx], legacyActions[idx], "GET"))
                    {
                        hits++;
                    }
                }
                BenchHarness.Sink += hits;
            });

            CompiledPermissionSet set = CompiledPermissionSet.Build(allowCodes);
            BenchResult modern = BenchHarness.Measure($"compiled N={endpointCount}", StandardIterations, iterations =>
            {
                long hits = 0;
                for (long i = 0; i < iterations; i++)
                {
                    int idx = (int)(i & QueryMask);
                    if (set.IsGranted(in modernQueries[idx]))
                    {
                        hits++;
                    }
                }
                BenchHarness.Sink += hits;
            });

            return (legacy, modern);
        }

        #endregion

        #region 场景 B：CompiledPermissionSet 微基准

        private static void RunScenarioMicroBenchmarks(StringBuilder report)
        {
            Console.WriteLine("[2/4] CompiledPermissionSet 微基准（10000 条权限代码，5% 通配符）...");

            var random = new Random(1337);
            (string[] allowCodes, List<string> exactCodes, List<string> wildcardPrefixes) = GenerateRealisticCodes(10_000);

            // 拒绝列表：另取 200 条精确代码同时列入 deny（拒绝优先）
            var denyCodes = new string[200];
            for (int i = 0; i < denyCodes.Length; i++)
            {
                denyCodes[i] = exactCodes[random.Next(exactCodes.Count)];
            }

            CompiledPermissionSet set = CompiledPermissionSet.Build(allowCodes, denyCodes);

            int queryCount = QueryMask + 1;
            var exactHit = new PermissionQuery[queryCount];
            var wildcardHit = new PermissionQuery[queryCount];
            var miss = new PermissionQuery[queryCount];
            var denyHit = new PermissionQuery[queryCount];
            var exactHitStrings = new string[queryCount];
            for (int i = 0; i < queryCount; i++)
            {
                string exactCode = exactCodes[random.Next(exactCodes.Count)];
                exactHit[i] = PermissionQuery.Parse(exactCode);
                exactHitStrings[i] = exactCode;
                // 通配命中：前缀存在通配规则、精确集合中不存在的动作
                wildcardHit[i] = PermissionQuery.Parse(wildcardPrefixes[random.Next(wildcardPrefixes.Count)] + ".export");
                miss[i] = PermissionQuery.Parse($"ghost{i % 97}.res{i % 31}.read");
                denyHit[i] = PermissionQuery.Parse(denyCodes[random.Next(denyCodes.Length)]);
            }

            BenchResult exactResult = MeasureEvaluate(set, exactHit, PermissionEffect.Allow, "精确命中");
            BenchResult wildcardResult = MeasureEvaluate(set, wildcardHit, PermissionEffect.Allow, "通配命中");
            BenchResult missResult = MeasureEvaluate(set, miss, PermissionEffect.NotSet, "未命中");
            BenchResult denyResult = MeasureEvaluate(set, denyHit, PermissionEffect.Deny, "deny 命中");

            // 预解析 PermissionQuery vs 每次传字符串（含解析/规范化）
            BenchResult stringResult = BenchHarness.Measure("字符串每次解析", StandardIterations, iterations =>
            {
                long hits = 0;
                for (long i = 0; i < iterations; i++)
                {
                    if (set.IsGranted(exactHitStrings[(int)(i & QueryMask)]))
                    {
                        hits++;
                    }
                }
                BenchHarness.Sink += hits;
            });

            report.AppendLine("## 场景 B：CompiledPermissionSet 微基准");
            report.AppendLine();
            report.AppendLine("10,000 条真实感权限代码（`mod{i}.res{j}.{read|write|delete}`，其中 5% 为通配符规则），外加 200 条 deny 规则。每轮 100 万次查询。");
            report.AppendLine();
            report.AppendLine("| 用例 | ns/op | ops/sec |");
            report.AppendLine("|---|---:|---:|");
            AppendRow(report, "精确命中（PermissionQuery）", exactResult);
            AppendRow(report, "通配命中（PermissionQuery）", wildcardResult);
            AppendRow(report, "未命中（PermissionQuery）", missResult);
            AppendRow(report, "deny 命中（PermissionQuery）", denyResult);
            AppendRow(report, "精确命中（每次传字符串，含解析）", stringResult);
            report.AppendLine();
            double parseOverhead = stringResult.NsPerOp - exactResult.NsPerOp;
            report.AppendLine($"**结论**：所有路径均为数十纳秒级，与 10,000 条规则的规模无关；" +
                $"`PermissionQuery` 预解析相比每次传字符串节省约 {BenchHarness.FormatNs(parseOverhead)} ns/op" +
                $"（约 {(stringResult.NsPerOp / exactResult.NsPerOp).ToString("N1", CultureInfo.InvariantCulture)} 倍差距），热路径（如端点固定权限）应预解析。");
            report.AppendLine();
        }

        private static BenchResult MeasureEvaluate(CompiledPermissionSet set, PermissionQuery[] queries, PermissionEffect expected, string name)
        {
            BenchResult result = BenchHarness.Measure(name, StandardIterations, iterations =>
            {
                long matched = 0;
                for (long i = 0; i < iterations; i++)
                {
                    if (set.Evaluate(in queries[(int)(i & QueryMask)]) == expected)
                    {
                        matched++;
                    }
                }
                BenchHarness.Sink += matched;
            });
            Console.WriteLine($"  {name}: {BenchHarness.FormatNs(result.NsPerOp)} ns/op");
            return result;
        }

        private static (string[] AllowCodes, List<string> ExactCodes, List<string> WildcardPrefixes) GenerateRealisticCodes(int count)
        {
            var allowCodes = new string[count];
            var exactCodes = new List<string>(count);
            var wildcardPrefixes = new List<string>();
            string[] actions = { "read", "write", "delete" };
            for (int i = 0; i < count; i++)
            {
                int mod = i / 300;
                int res = (i / 3) % 100;
                if (i % 20 == 0)
                {
                    // 5% 通配符规则
                    allowCodes[i] = $"mod{mod}.res{res}.*";
                    wildcardPrefixes.Add($"mod{mod}.res{res}");
                }
                else
                {
                    allowCodes[i] = $"mod{mod}.res{res}.{actions[i % 3]}";
                    exactCodes.Add(allowCodes[i]);
                }
            }
            return (allowCodes, exactCodes, wildcardPrefixes);
        }

        #endregion

        #region 场景 C：构建成本

        private static void RunScenarioBuildCost(StringBuilder report)
        {
            Console.WriteLine("[3/4] CompiledPermissionSet.Build 构建成本 ...");
            (string[] allowCodes, _, _) = GenerateRealisticCodes(10_000);

            // 预热
            for (int i = 0; i < 2; i++)
            {
                BenchHarness.Sink += CompiledPermissionSet.Build(allowCodes).Allows.Count;
            }

            var times = new double[10];
            for (int i = 0; i < times.Length; i++)
            {
                Stopwatch sw = Stopwatch.StartNew();
                CompiledPermissionSet set = CompiledPermissionSet.Build(allowCodes);
                sw.Stop();
                times[i] = sw.Elapsed.TotalMilliseconds;
                BenchHarness.Sink += set.Allows.Count;
            }

            double sum = 0;
            foreach (double t in times)
            {
                sum += t;
            }
            double avg = sum / times.Length;
            double median = BenchHarness.Median(times);
            Console.WriteLine($"  Build(10000): 平均 {BenchHarness.FormatMs(avg)} ms");

            report.AppendLine("## 场景 C：构建成本");
            report.AppendLine();
            report.AppendLine("`CompiledPermissionSet.Build` 编译 10,000 条权限代码（含规范化、去重、通配符 Trie 构建），10 次取平均。");
            report.AppendLine();
            report.AppendLine("| 指标 | 数值 |");
            report.AppendLine("|---|---:|");
            report.AppendLine($"| 平均耗时 | {BenchHarness.FormatMs(avg)} ms |");
            report.AppendLine($"| 中位耗时 | {BenchHarness.FormatMs(median)} ms |");
            report.AppendLine($"| 单条摊销 | {BenchHarness.FormatNs(avg * 1_000_000 / 10_000)} ns/条 |");
            report.AppendLine();
            report.AppendLine("**结论**：万条规模的权限集编译为毫秒级一次性成本，配合缓存与版本失效，重建开销可忽略。");
            report.AppendLine();
        }

        #endregion

        #region 场景 D：端到端 PermissionEvaluator

        private static async Task RunScenarioEndToEndAsync(StringBuilder report)
        {
            Console.WriteLine("[4/4] PermissionEvaluator 端到端（DI + InMemoryStore + 1000 权限用户）...");

            // 首次构建（缓存未命中）：5 个全新容器分别测一次，取中位数
            var coldTimes = new double[5];
            for (int i = 0; i < coldTimes.Length; i++)
            {
                (IPermissionEvaluator evaluator, AuthSubject subject, PermissionQuery query) = await CreateEvaluatorAsync();
                Stopwatch sw = Stopwatch.StartNew();
                var decision = await evaluator.EvaluateAsync(subject, query);
                sw.Stop();
                coldTimes[i] = sw.Elapsed.TotalMilliseconds;
                BenchHarness.Sink += decision.IsGranted ? 1 : 0;
            }
            double coldMedianMs = BenchHarness.Median(coldTimes);

            // 热路径（缓存命中）：单线程 100 万次
            (IPermissionEvaluator warmEvaluator, AuthSubject warmSubject, PermissionQuery warmQuery) = await CreateEvaluatorAsync();
            await warmEvaluator.EvaluateAsync(warmSubject, warmQuery); // 触发缓存构建

            BenchResult single = BenchHarness.Measure("单线程缓存命中", StandardIterations, iterations =>
            {
                RunEvaluateLoopAsync(warmEvaluator, warmSubject, warmQuery, iterations).GetAwaiter().GetResult();
            });
            Console.WriteLine($"  单线程: {BenchHarness.FormatNs(single.NsPerOp)} ns/op, {BenchHarness.FormatOps(single.OpsPerSecond)} ops/sec");

            // 并行：8 线程 × 125,000 次 = 100 万次
            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = 8 };
            BenchResult parallel = BenchHarness.Measure("8 线程并行缓存命中", StandardIterations, iterations =>
            {
                long perThread = iterations / 8;
                Parallel.For(0, 8, parallelOptions, _ =>
                {
                    RunEvaluateLoopAsync(warmEvaluator, warmSubject, warmQuery, perThread).GetAwaiter().GetResult();
                });
            });
            Console.WriteLine($"  8 线程: {BenchHarness.FormatOps(parallel.OpsPerSecond)} ops/sec");

            report.AppendLine("## 场景 D：端到端 PermissionEvaluator.EvaluateAsync");
            report.AppendLine();
            report.AppendLine("真实 DI 容器（`AddCyaimAuthCore().AddInMemoryStore()`）+ 拥有 1,000 条直接权限的用户，走完整评估管线（缓存查找、决策、指标记录）。");
            report.AppendLine();
            report.AppendLine("| 用例 | ns/op | ops/sec |");
            report.AppendLine("|---|---:|---:|");
            AppendRow(report, "缓存命中（单线程，100 万次/轮）", single);
            AppendRow(report, "缓存命中（Parallel.For 8 线程 × 12.5 万次）", parallel);
            report.AppendLine();
            report.AppendLine($"**首次构建（缓存未命中）**：{BenchHarness.FormatMs(coldMedianMs)} ms（中位数，含用户存储查询 + 1,000 条权限编译；仅在首次评估或缓存失效时发生一次）。");
            report.AppendLine();
            report.AppendLine($"**结论**：缓存命中路径单次评估约 {BenchHarness.FormatNs(single.NsPerOp)} ns，" +
                $"单线程约 {BenchHarness.FormatOps(single.OpsPerSecond)} ops/sec；8 线程并行约 {BenchHarness.FormatOps(parallel.OpsPerSecond)} ops/sec" +
                $"（并行加速 {(parallel.OpsPerSecond / single.OpsPerSecond).ToString("N1", CultureInfo.InvariantCulture)}x）。评估器读路径无锁，可随核数扩展。");
            report.AppendLine();
        }

        private static async Task RunEvaluateLoopAsync(IPermissionEvaluator evaluator, AuthSubject subject, PermissionQuery query, long iterations)
        {
            long granted = 0;
            for (long i = 0; i < iterations; i++)
            {
                var decision = await evaluator.EvaluateAsync(subject, query).ConfigureAwait(false);
                if (decision.IsGranted)
                {
                    granted++;
                }
            }
            BenchHarness.Sink += granted;
        }

        private static async Task<(IPermissionEvaluator Evaluator, AuthSubject Subject, PermissionQuery Query)> CreateEvaluatorAsync()
        {
            var services = new ServiceCollection();
            services.AddCyaimAuthCore(o =>
            {
                o.PermissionCacheTtl = TimeSpan.FromHours(1);
            }).AddInMemoryStore();
            ServiceProvider provider = services.BuildServiceProvider();

            // 1000 条互不相同的直接权限
            var permissions = new List<string>(1000);
            for (int i = 0; i < 1000; i++)
            {
                permissions.Add($"m{i / 50}.r{(i % 50) / 5}.a{i % 5}");
            }

            var user = new AuthUser
            {
                Id = "bench-user",
                UserName = "bench",
                DirectPermissions = permissions,
            };
            IUserStore userStore = provider.GetRequiredService<IUserStore>();
            await userStore.CreateAsync(user);

            var subject = new AuthSubject
            {
                Id = user.Id,
                Name = user.UserName,
                IsAuthenticated = true,
                SubjectType = AuthSubjectType.User,
            };

            IPermissionEvaluator evaluator = provider.GetRequiredService<IPermissionEvaluator>();
            PermissionQuery query = PermissionQuery.Parse("m0.r0.a0");
            return (evaluator, subject, query);
        }

        #endregion

        private static void AppendRow(StringBuilder report, string label, BenchResult result)
        {
            report.AppendLine($"| {label} | {BenchHarness.FormatNs(result.NsPerOp)} | {BenchHarness.FormatOps(result.OpsPerSecond)} |");
        }

        private static string FindRepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Cyaim.Authentication.sln")))
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }
            // 回退：当前工作目录
            return Directory.GetCurrentDirectory();
        }
    }
}
