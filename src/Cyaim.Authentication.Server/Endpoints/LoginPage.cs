using System.Text.Encodings.Web;

namespace Cyaim.Authentication.Server.Endpoints
{
    /// <summary>
    /// 内嵌登录页与登出页 HTML（内联 CSS，深浅色自适应）。
    /// </summary>
    internal static class LoginPage
    {
        /// <summary>
        /// 渲染登录页。
        /// </summary>
        /// <param name="serverName">页面标题（服务器名称）</param>
        /// <param name="loginPath">表单提交地址</param>
        /// <param name="returnUrl">登录成功后跳转地址（写入隐藏域）</param>
        /// <param name="showError">是否显示凭据错误提示</param>
        public static string Render(string serverName, string loginPath, string? returnUrl, bool showError)
        {
            HtmlEncoder encoder = HtmlEncoder.Default;
            string safeName = encoder.Encode(serverName);
            string safeAction = encoder.Encode(loginPath);
            string safeReturnUrl = string.IsNullOrEmpty(returnUrl) ? string.Empty : encoder.Encode(returnUrl!);
            string errorBlock = showError
                ? "<div class=\"error\" role=\"alert\">用户名或密码不正确，请重试</div>"
                : string.Empty;

            return $$"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>登录 - {{safeName}}</title>
<style>
:root {
  --bg: #f2f4f8;
  --card-bg: #ffffff;
  --text: #1a202c;
  --text-muted: #64748b;
  --border: #d7dce3;
  --accent: #2563eb;
  --accent-hover: #1d4ed8;
  --error-bg: #fef2f2;
  --error-border: #fca5a5;
  --error-text: #b91c1c;
  --shadow: 0 8px 24px rgba(15, 23, 42, .08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f172a;
    --card-bg: #1e293b;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --border: #334155;
    --accent: #3b82f6;
    --accent-hover: #60a5fa;
    --error-bg: #451a1a;
    --error-border: #7f1d1d;
    --error-text: #fca5a5;
    --shadow: 0 8px 24px rgba(0, 0, 0, .4);
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}
.card {
  width: 100%;
  max-width: 380px;
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: var(--shadow);
  padding: 2.25rem 2rem;
}
h1 { font-size: 1.35rem; font-weight: 600; text-align: center; }
.sub { color: var(--text-muted); font-size: .875rem; text-align: center; margin: .5rem 0 1.5rem; }
.error {
  background: var(--error-bg);
  border: 1px solid var(--error-border);
  color: var(--error-text);
  border-radius: 8px;
  padding: .625rem .875rem;
  font-size: .85rem;
  margin-bottom: 1rem;
}
label { display: block; font-size: .85rem; color: var(--text-muted); margin-bottom: 1rem; }
input[type=text], input[type=password] {
  width: 100%;
  margin-top: .35rem;
  padding: .625rem .75rem;
  font-size: .95rem;
  color: var(--text);
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 8px;
  outline: none;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }
button {
  width: 100%;
  padding: .7rem;
  margin-top: .25rem;
  font-size: .95rem;
  font-weight: 600;
  color: #fff;
  background: var(--accent);
  border: none;
  border-radius: 8px;
  cursor: pointer;
}
button:hover { background: var(--accent-hover); }
</style>
</head>
<body>
<main class="card">
  <h1>{{safeName}}</h1>
  <p class="sub">请登录以继续</p>
  {{errorBlock}}
  <form method="post" action="{{safeAction}}">
    <input type="hidden" name="returnUrl" value="{{safeReturnUrl}}">
    <label>用户名
      <input type="text" name="username" autocomplete="username" required autofocus>
    </label>
    <label>密码
      <input type="password" name="password" autocomplete="current-password" required>
    </label>
    <button type="submit">登 录</button>
  </form>
</main>
</body>
</html>
""";
        }

        /// <summary>
        /// 渲染已登出页。
        /// </summary>
        public static string RenderLoggedOut(string serverName)
        {
            string safeName = HtmlEncoder.Default.Encode(serverName);
            return $$"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>已登出 - {{safeName}}</title>
<style>
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
  background: #f2f4f8; color: #1a202c;
  min-height: 100vh; margin: 0;
  display: flex; align-items: center; justify-content: center;
}
@media (prefers-color-scheme: dark) {
  body { background: #0f172a; color: #e2e8f0; }
}
.box { text-align: center; }
h1 { font-size: 1.25rem; font-weight: 600; }
p { color: #64748b; font-size: .9rem; }
</style>
</head>
<body>
<main class="box">
  <h1>您已安全登出</h1>
  <p>{{safeName}} 会话已结束，可以关闭此页面。</p>
</main>
</body>
</html>
""";
        }
    }
}
