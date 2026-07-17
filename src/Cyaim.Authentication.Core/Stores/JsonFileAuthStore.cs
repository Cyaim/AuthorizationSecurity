using System;
using System.IO;
using System.Text.Json;
using System.Threading;

namespace Cyaim.Authentication.Core.Stores
{
    /// <summary>
    /// JSON 文件持久化授权存储：内存语义 + 防抖异步落盘（临时文件替换，掉电安全）。
    /// 适用于中小型独立部署；大规模场景请针对数据库实现存储接口。
    /// </summary>
    public sealed class JsonFileAuthStore : InMemoryAuthStore, IDisposable
    {
        private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
        };

        private readonly string _filePath;
        private readonly Timer _saveTimer;
        private readonly TimeSpan _debounce;
        private readonly object _saveGate = new object();
        private int _pendingSave;
        private bool _loaded;

        /// <summary>
        /// 打开或创建 JSON 文件存储。
        /// </summary>
        /// <param name="filePath">存储文件路径</param>
        /// <param name="debounceMilliseconds">写盘防抖间隔（毫秒），默认 500</param>
        public JsonFileAuthStore(string filePath, int debounceMilliseconds = 500)
        {
            _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
            _debounce = TimeSpan.FromMilliseconds(Math.Max(0, debounceMilliseconds));
            // 定时器回调运行在 ThreadPool 线程；其中的未处理异常会终止进程，故必须吞掉 IO 异常。
            _saveTimer = new Timer(_ => TrySaveFromTimer(), null, Timeout.Infinite, Timeout.Infinite);

            Load();
            _loaded = true;
        }

        /// <summary>最近一次后台落盘的异常（供诊断；正常为 null）</summary>
        public Exception? LastSaveError { get; private set; }

        private void TrySaveFromTimer()
        {
            try
            {
                SaveNow();
                LastSaveError = null;
            }
            catch (Exception ex)
            {
                // 落盘失败不应终止进程；保留待保存标记，下次变更时重试。
                LastSaveError = ex;
                Interlocked.Exchange(ref _pendingSave, 1);
            }
        }

        /// <inheritdoc/>
        protected override void OnMutated()
        {
            if (!_loaded)
            {
                return;
            }

            Interlocked.Exchange(ref _pendingSave, 1);
            _saveTimer.Change(_debounce, Timeout.InfiniteTimeSpan);
        }

        private void Load()
        {
            if (!File.Exists(_filePath))
            {
                return;
            }

            byte[] json = File.ReadAllBytes(_filePath);
            if (json.Length == 0)
            {
                return;
            }

            Snapshot? snapshot = JsonSerializer.Deserialize<Snapshot>(json, SerializerOptions);
            if (snapshot != null)
            {
                ImportSnapshot(snapshot);
            }
        }

        /// <summary>
        /// 立即写盘（正常退出前可调用；平时由防抖定时器触发）。
        /// </summary>
        public void SaveNow()
        {
            if (Interlocked.Exchange(ref _pendingSave, 0) == 0 && _loaded)
            {
                // 没有待保存变更时也允许显式调用强制写盘
            }

            lock (_saveGate)
            {
                Snapshot snapshot = ExportSnapshot();
                string? dir = Path.GetDirectoryName(Path.GetFullPath(_filePath));
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string tempPath = _filePath + ".tmp";
                File.WriteAllBytes(tempPath, JsonSerializer.SerializeToUtf8Bytes(snapshot, SerializerOptions));

                if (File.Exists(_filePath))
                {
                    File.Replace(tempPath, _filePath, destinationBackupFileName: null);
                }
                else
                {
                    File.Move(tempPath, _filePath);
                }
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            _saveTimer.Dispose();
            if (Interlocked.CompareExchange(ref _pendingSave, 0, 1) == 1)
            {
                // 落盘异常不应从 Dispose 抛出（using 块、DI 释放等场景会被放大为二次异常）
                try
                {
                    SaveNow();
                }
                catch (Exception ex)
                {
                    LastSaveError = ex;
                }
            }
        }
    }
}
