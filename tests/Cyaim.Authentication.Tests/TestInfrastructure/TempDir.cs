using System;
using System.IO;

namespace Cyaim.Authentication.Tests.TestInfrastructure
{
    /// <summary>
    /// 测试用临时目录：位于 %TEMP%/cyaim-tests/&lt;Guid&gt;，Dispose 时清理。
    /// </summary>
    public sealed class TempDir : IDisposable
    {
        /// <summary>目录完整路径</summary>
        public string Path { get; }

        /// <summary>创建唯一临时目录</summary>
        public TempDir()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(), "cyaim-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        /// <summary>获取目录内文件的完整路径</summary>
        public string File(string name) => System.IO.Path.Combine(Path, name);

        /// <inheritdoc/>
        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
                // 清理失败不影响测试结果
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }
}
