using System;
using System.Text.Json;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Authorization;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Cyaim.Authentication.AspNetCore
{
    /// <summary>
    /// 权限中间件：解析令牌 → 构建主体 → 按端点元数据执行权限判断。
    /// 须置于 UseRouting 之后（WebApplication 最简主机下直接 app.UseCyaimAuthentication() 即可）。
    /// WebSocket 握手请求同样经过此检查，握手前即完成鉴权。
    /// </summary>
    public class CyaimAuthMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ITokenService _tokenService;
        private readonly IPermissionEvaluator _evaluator;
        private readonly EndpointPermissionResolver _resolver;
        private readonly IAuditLogger _audit;
        private readonly IOptions<CyaimAuthOptions> _options;
        private readonly ILogger<CyaimAuthMiddleware> _logger;

        /// <summary>创建中间件</summary>
        public CyaimAuthMiddleware(
            RequestDelegate next,
            ITokenService tokenService,
            IPermissionEvaluator evaluator,
            EndpointPermissionResolver resolver,
            IAuditLogger audit,
            IOptions<CyaimAuthOptions> options,
            ILogger<CyaimAuthMiddleware> logger)
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _tokenService = tokenService;
            _evaluator = evaluator;
            _resolver = resolver;
            _audit = audit;
            _options = options;
            _logger = logger;
        }

        /// <summary>中间件入口</summary>
        public async Task InvokeAsync(HttpContext context)
        {
            CyaimAuthOptions options = _options.Value;

            // 1. 解析令牌与主体
            string? token = ExtractToken(context, options);
            AuthSubject subject;
            TokenState tokenState;
            if (token == null)
            {
                subject = AuthSubject.Guest(options.GuestRoles);
                tokenState = TokenState.None;
            }
            else
            {
                AccessTokenValidation validation = await _tokenService.ValidateAccessTokenAsync(token, context.RequestAborted);
                if (validation.IsValid && validation.Subject != null)
                {
                    subject = validation.Subject;
                    tokenState = TokenState.Valid;
                    if (validation.Principal != null)
                    {
                        context.User = validation.Principal;
                    }
                }
                else
                {
                    subject = AuthSubject.Guest(options.GuestRoles);
                    tokenState = TokenState.Invalid;
                }
            }

            context.Features.Set<ICyaimAuthFeature>(new CyaimAuthFeature(subject, tokenState));

            // 2. 端点权限要求
            EndpointRequirement? requirement = _resolver.GetRequirement(context.GetEndpoint());
            if (requirement == null || requirement.AllowAnonymous)
            {
                await _next(context);
                return;
            }

            // 3. 未认证：401（区分无令牌与无效令牌，RFC 6750 §3）
            if (!subject.IsAuthenticated)
            {
                // 游客角色可能持有权限，先评估
                AuthorizationDecision? guestDecision = await EvaluateRequirementAsync(context, subject, requirement);
                if (guestDecision == null)
                {
                    await _next(context);
                    return;
                }

                await DenyAsync(context, guestDecision, statusCode: StatusCodes.Status401Unauthorized,
                    error: tokenState == TokenState.Invalid ? "invalid_token" : "unauthorized");
                return;
            }

            // 4. 已认证：评估权限
            AuthorizationDecision? decision = await EvaluateRequirementAsync(context, subject, requirement);
            if (decision == null)
            {
                await _next(context);
                return;
            }

            await DenyAsync(context, decision, StatusCodes.Status403Forbidden, "forbidden");
        }

        /// <summary>
        /// 评估端点全部规则；通过返回 null，拒绝返回具体结论。
        /// </summary>
        private async Task<AuthorizationDecision?> EvaluateRequirementAsync(HttpContext context, AuthSubject subject, EndpointRequirement requirement)
        {
            // 无具体权限码可判定的端点（仅要求已认证、或纯 ABAC 策略），主体失效状态不会被
            // 后续的权限判断覆盖，需在此显式确认：账户被禁用/锁定，或口令重置后安全戳不一致时拒绝。
            // （含权限码的端点由 EvaluateAsync 自身返回 SubjectDisabled，无需重复检查，热路径零额外开销。）
            if (subject.IsAuthenticated && !RequirementHasPermissionQueries(requirement))
            {
                bool active = await _evaluator.IsSubjectActiveAsync(subject, context.RequestAborted);
                if (!active)
                {
                    return AuthorizationDecision.Denied(AuthorizationReason.SubjectDisabled);
                }
            }

            if (requirement.Rules.Length == 0)
            {
                // 仅要求已认证
                return subject.IsAuthenticated
                    ? null
                    : AuthorizationDecision.Denied(AuthorizationReason.GuestNotAllowed);
            }

            foreach (PermissionRule rule in requirement.Rules)
            {
                if (rule.HasInvalidCode)
                {
                    return AuthorizationDecision.Denied(AuthorizationReason.InvalidPermissionCode);
                }

                if (rule.Queries.Length == 0 && rule.Policy == null && !subject.IsAuthenticated)
                {
                    return AuthorizationDecision.Denied(AuthorizationReason.GuestNotAllowed);
                }

                if (rule.Queries.Length > 0)
                {
                    AuthorizationDecision? denied = await EvaluateCodesAsync(context, subject, rule);
                    if (denied != null)
                    {
                        return denied;
                    }
                }

                if (rule.Policy != null)
                {
                    var policyContext = new AuthorizationContext
                    {
                        Subject = subject,
                        UnderlyingContext = context,
                    };
                    AuthorizationDecision policyDecision = await _evaluator.EvaluatePolicyAsync(subject, rule.Policy, policyContext, context.RequestAborted);
                    if (!policyDecision.IsGranted)
                    {
                        return policyDecision;
                    }
                }
            }

            return null;
        }

        private static bool RequirementHasPermissionQueries(EndpointRequirement requirement)
        {
            foreach (PermissionRule rule in requirement.Rules)
            {
                if (rule.Queries.Length > 0)
                {
                    return true;
                }
            }
            return false;
        }

        private async Task<AuthorizationDecision?> EvaluateCodesAsync(HttpContext context, AuthSubject subject, PermissionRule rule)
        {
            AuthorizationDecision? lastDenied = null;
            foreach (PermissionQuery query in rule.Queries)
            {
                AuthorizationDecision decision = await _evaluator.EvaluateAsync(subject, query, null, context.RequestAborted);
                if (rule.RequireAll)
                {
                    if (!decision.IsGranted)
                    {
                        return decision;
                    }
                }
                else
                {
                    if (decision.IsGranted)
                    {
                        return null;
                    }
                    lastDenied = decision;
                }
            }

            return rule.RequireAll ? null : lastDenied;
        }

        private async Task DenyAsync(HttpContext context, AuthorizationDecision decision, int statusCode, string error)
        {
            CyaimAuthOptions options = _options.Value;
            ICyaimAuthFeature feature = context.Features.Get<ICyaimAuthFeature>()!;

            _logger.LogWarning(AuthLogEvents.RequestDenied,
                "请求被拒绝 {Method} {Path} subject={SubjectId} status={Status} reason={Reason} permission={Permission}",
                context.Request.Method, context.Request.Path, feature.Subject.Id, statusCode, decision.Reason, decision.PermissionCode);

            if (options.AuditDenials)
            {
                await _audit.WriteAsync(new AuditEvent
                {
                    Category = AuditCategory.PermissionCheck,
                    Outcome = AuditOutcome.Denied,
                    SubjectId = feature.Subject.Id,
                    SubjectName = feature.Subject.Name,
                    ClientId = feature.Subject.ClientId,
                    Resource = context.Request.Path.Value,
                    Action = context.Request.Method,
                    Detail = $"{decision.Reason}{(decision.PermissionCode == null ? string.Empty : ": " + decision.PermissionCode)}",
                    RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
                }, context.RequestAborted);
            }

            if (options.OnDenied != null)
            {
                await options.OnDenied(context, decision);
                return;
            }

            context.Response.StatusCode = statusCode;
            if (statusCode == StatusCodes.Status401Unauthorized)
            {
                context.Response.Headers["WWW-Authenticate"] = error == "invalid_token"
                    ? "Bearer error=\"invalid_token\""
                    : "Bearer";
            }
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                error,
                error_description = decision.Reason.ToString(),
                permission = decision.PermissionCode,
            }), context.RequestAborted);
        }

        private static string? ExtractToken(HttpContext context, CyaimAuthOptions options)
        {
            // Authorization: Bearer xxx
            if (context.Request.Headers.TryGetValue(options.AuthorizationHeaderName, out StringValues header) && header.Count > 0)
            {
                string value = header.ToString();
                if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return value.Substring(7).Trim();
                }
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }

            // ?access_token=xxx（WebSocket 握手等场景）
            if (options.AllowTokenFromQuery &&
                context.Request.Query.TryGetValue(options.QueryTokenParameter, out StringValues query) && query.Count > 0)
            {
                string value = query.ToString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            // Cookie
            if (options.AllowTokenFromCookie &&
                context.Request.Cookies.TryGetValue(options.CookieTokenName, out string? cookie) &&
                !string.IsNullOrWhiteSpace(cookie))
            {
                return cookie;
            }

            return null;
        }
    }
}
