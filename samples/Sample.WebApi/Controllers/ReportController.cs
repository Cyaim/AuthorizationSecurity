// 控制器形态的权限标注示例（与 Minimal API 等效）。
using Cyaim.Authentication.Abstractions;
using Microsoft.AspNetCore.Mvc;

namespace Sample.WebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[RequirePermission("demo.report")]                       // 控制器级：访问任何动作都需要
public class ReportController : ControllerBase
{
    [HttpGet]
    [RequirePermission("demo.report.read")]              // 动作级：与控制器级同时要求
    public IActionResult List() => Ok(new[] { "日报", "月报" });

    [HttpGet("ping")]
    [AllowGuest]                                         // 覆盖控制器级要求
    public IActionResult Ping() => Ok("pong");
}
