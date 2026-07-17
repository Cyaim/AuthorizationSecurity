using System;
using System.Diagnostics;
using System.Globalization;

namespace Cyaim.Authentication.Benchmarks
{
    /// <summary>
    /// 单个基准场景的测量结果。
    /// </summary>
    public sealed class BenchResult
    {
        /// <summary>场景名称</summary>
        public string Name { get; }

        /// <summary>每轮迭代（操作）次数</summary>
        public long Iterations { get; }

        /// <summary>每操作耗时中位数（纳秒）</summary>
        public double NsPerOp { get; }

        /// <summary>每秒操作数（按中位数轮次折算）</summary>
        public double OpsPerSecond { get; }

        /// <summary>各正式轮次耗时（毫秒）</summary>
        public double[] RoundMilliseconds { get; }

        /// <summary>
        /// 创建结果。
        /// </summary>
        public BenchResult(string name, long iterations, double nsPerOp, double opsPerSecond, double[] roundMilliseconds)
        {
            Name = name;
            Iterations = iterations;
            NsPerOp = nsPerOp;
            OpsPerSecond = opsPerSecond;
            RoundMilliseconds = roundMilliseconds;
        }
    }

    /// <summary>
    /// 轻量测量 harness：预热 N 轮 + 正式 M 轮取中位数，基于 <see cref="Stopwatch"/>。
    /// </summary>
    public static class BenchHarness
    {
        /// <summary>防止被 JIT 消除的黑洞汇聚点</summary>
        public static long Sink;

        /// <summary>
        /// 执行测量。<paramref name="body"/> 自行完成 <paramref name="iterations"/> 次操作的内部循环。
        /// </summary>
        /// <param name="name">场景名称</param>
        /// <param name="iterations">每轮操作次数</param>
        /// <param name="body">被测循环体（参数为迭代次数）</param>
        /// <param name="warmupRounds">预热轮数（默认 2）</param>
        /// <param name="measuredRounds">正式轮数（默认 5，取中位数）</param>
        public static BenchResult Measure(string name, long iterations, Action<long> body, int warmupRounds = 2, int measuredRounds = 5)
        {
            for (int i = 0; i < warmupRounds; i++)
            {
                body(iterations);
            }

            double[] rounds = new double[measuredRounds];
            for (int i = 0; i < measuredRounds; i++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                Stopwatch sw = Stopwatch.StartNew();
                body(iterations);
                sw.Stop();
                rounds[i] = sw.Elapsed.TotalMilliseconds;
            }

            double medianMs = Median(rounds);
            double nsPerOp = medianMs * 1_000_000.0 / iterations;
            double opsPerSec = iterations / (medianMs / 1000.0);
            return new BenchResult(name, iterations, nsPerOp, opsPerSec, rounds);
        }

        /// <summary>
        /// 计算中位数（不修改输入数组）。
        /// </summary>
        public static double Median(double[] values)
        {
            double[] sorted = (double[])values.Clone();
            Array.Sort(sorted);
            int mid = sorted.Length / 2;
            return sorted.Length % 2 == 1
                ? sorted[mid]
                : (sorted[mid - 1] + sorted[mid]) / 2.0;
        }

        /// <summary>
        /// 格式化 ns/op（保留 1 位小数，含千分位）。
        /// </summary>
        public static string FormatNs(double ns) => ns.ToString("N1", CultureInfo.InvariantCulture);

        /// <summary>
        /// 格式化 ops/sec（千分位整数）。
        /// </summary>
        public static string FormatOps(double ops) => ops.ToString("N0", CultureInfo.InvariantCulture);

        /// <summary>
        /// 格式化毫秒（保留 2 位小数）。
        /// </summary>
        public static string FormatMs(double ms) => ms.ToString("N2", CultureInfo.InvariantCulture);
    }
}
