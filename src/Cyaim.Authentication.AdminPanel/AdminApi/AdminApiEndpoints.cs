using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Cyaim.Authentication.Abstractions;
using Cyaim.Authentication.Abstractions.Models;
using Cyaim.Authentication.Abstractions.Permissions;
using Cyaim.Authentication.Abstractions.Services;
using Cyaim.Authentication.Abstractions.Stores;
using Cyaim.Authentication.Core.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using AdminPermissions = Cyaim.Authentication.Abstractions.AuthConstants.AdminPermissions;

namespace Cyaim.Authentication.AdminPanel
{
    /// <summary>
    /// 管理 REST API 端点（挂载在面板 BasePath/api 下）。
    /// </summary>
    internal static class AdminApiEndpoints
    {
        /// <summary>统一 JSON 序列化配置：camelCase 属性、枚举字符串化。</summary>
        internal static readonly JsonSerializerOptions Json = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() },
        };

        /// <summary>
        /// 注册全部管理 API。
        /// </summary>
        internal static void Map(RouteGroupBuilder group)
        {
            RouteGroupBuilder api = group.MapGroup("/api");

            // 注意：统一转为 Delegate，避免 Task&lt;IResult&gt;(HttpContext) 签名被当作 RequestDelegate 而丢弃返回值（ASP0016）

            // 匿名：SPA 启动配置
            api.MapGet("/config", (Delegate)GetConfig).AllowGuest();

            // 已认证即可：当前主体信息与管理权限判定
            api.MapGet("/me", (Delegate)GetMe).RequirePermission();

            // 仪表盘（Read 或任一管理权限）
            api.MapGet("/stats", (Delegate)GetStats).RequirePermission(
                AdminPermissions.Read, AdminPermissions.ManageUsers, AdminPermissions.ManageRoles,
                AdminPermissions.ManagePermissions, AdminPermissions.ManageClients, AdminPermissions.ReadAudit);

            // 用户管理
            api.MapGet("/users", (Delegate)ListUsers).RequirePermission(AdminPermissions.Read, AdminPermissions.ManageUsers);
            api.MapPost("/users", (Delegate)CreateUser).RequirePermission(AdminPermissions.ManageUsers);
            api.MapPut("/users/{id}", (Delegate)UpdateUser).RequirePermission(AdminPermissions.ManageUsers);
            api.MapPost("/users/{id}/reset-password", (Delegate)ResetUserPassword).RequirePermission(AdminPermissions.ManageUsers);
            api.MapDelete("/users/{id}", (Delegate)DeleteUser).RequirePermission(AdminPermissions.ManageUsers);

            // 角色管理
            api.MapGet("/roles", (Delegate)ListRoles).RequirePermission(AdminPermissions.Read, AdminPermissions.ManageRoles);
            api.MapPost("/roles", (Delegate)CreateRole).RequirePermission(AdminPermissions.ManageRoles);
            api.MapPut("/roles/{id}", (Delegate)UpdateRole).RequirePermission(AdminPermissions.ManageRoles);
            api.MapDelete("/roles/{id}", (Delegate)DeleteRole).RequirePermission(AdminPermissions.ManageRoles);

            // 权限定义
            api.MapGet("/permissions", (Delegate)ListPermissions).RequirePermission(AdminPermissions.Read, AdminPermissions.ManagePermissions);
            api.MapPost("/permissions", (Delegate)UpsertPermissions).RequirePermission(AdminPermissions.ManagePermissions);
            api.MapDelete("/permissions/{code}", (Delegate)DeletePermission).RequirePermission(AdminPermissions.ManagePermissions);

            // 客户端管理
            api.MapGet("/clients", (Delegate)ListClients).RequirePermission(AdminPermissions.Read, AdminPermissions.ManageClients);
            api.MapPost("/clients", (Delegate)CreateClient).RequirePermission(AdminPermissions.ManageClients);
            api.MapPut("/clients/{id}", (Delegate)UpdateClient).RequirePermission(AdminPermissions.ManageClients);
            api.MapPost("/clients/{id}/regenerate-secret", (Delegate)RegenerateClientSecret).RequirePermission(AdminPermissions.ManageClients);
            api.MapDelete("/clients/{id}", (Delegate)DeleteClient).RequirePermission(AdminPermissions.ManageClients);

            // 审计日志
            api.MapGet("/audit", (Delegate)QueryAudit).RequirePermission(AdminPermissions.ReadAudit);
        }

        // ---------------------------------------------------------------- 基础

        private static IResult Ok(object? data) => Results.Json(data, Json);

        private static IResult Created(object? data) => Results.Json(data, Json, statusCode: StatusCodes.Status201Created);

        private static IResult Error(int statusCode, string message) =>
            Results.Json(new Dictionary<string, string> { ["error"] = message }, Json, statusCode: statusCode);

        private static async Task<T?> ReadJsonAsync<T>(HttpContext context) where T : class
        {
            if (!context.Request.HasJsonContentType())
            {
                return null;
            }
            try
            {
                return await context.Request.ReadFromJsonAsync<T>(Json, context.RequestAborted);
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static int ParseInt(HttpContext context, string name, int defaultValue, int min, int max)
        {
            string? raw = context.Request.Query[name];
            if (!int.TryParse(raw, out int value))
            {
                value = defaultValue;
            }
            return Math.Max(min, Math.Min(max, value));
        }

        /// <summary>
        /// 职责分离守卫：授予/修改权限或角色时，要求调用者本身具备对应的管理权限，
        /// 防止仅持 ManageUsers 的委派管理员通过编辑用户为自己授予任意权限而纵向越权。
        /// 满足返回 null，否则返回 403。
        /// </summary>
        private static async Task<IResult?> RequireManageAsync(HttpContext context, string permission, CancellationToken ct)
        {
            IPermissionEvaluator evaluator = context.RequestServices.GetRequiredService<IPermissionEvaluator>();
            if (await evaluator.IsGrantedAsync(context.GetAuthSubject(), permission, ct))
            {
                return null;
            }
            return Error(StatusCodes.Status403Forbidden, $"该操作涉及授予权限或角色，需要 {permission} 权限");
        }

        /// <summary>
        /// 校验权限代码列表格式（拒绝无法规范化的代码），非法即 400。
        /// 防止非法拒绝代码被静默丢弃导致 deny 规则不生效。
        /// </summary>
        private static IResult? ValidatePermissionCodes(params IEnumerable<string>?[] codeLists)
        {
            foreach (IEnumerable<string>? list in codeLists)
            {
                if (list == null)
                {
                    continue;
                }
                foreach (string code in list)
                {
                    if (!PermissionCode.TryNormalize(code, out _, out string? error))
                    {
                        return Error(StatusCodes.Status400BadRequest, $"非法权限代码 \"{code}\"：{error}");
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// 吊销主体的全部刷新令牌（口令重置/禁用/删除用户后调用，使已签发会话失效）。
        /// </summary>
        private static Task RevokeSubjectTokensAsync(HttpContext context, string subjectId, CancellationToken ct)
        {
            var manager = context.RequestServices.GetService<Cyaim.Authentication.Core.Tokens.RefreshTokenManager>();
            return manager?.RevokeAllForSubjectAsync(subjectId, null, ct) ?? Task.CompletedTask;
        }

        /// <summary>
        /// 写入管理操作审计（Category=Admin）。
        /// </summary>
        private static Task WriteAdminAuditAsync(HttpContext context, string resource, string action, string? detail = null)
        {
            IAuditLogger audit = context.RequestServices.GetRequiredService<IAuditLogger>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();
            AuthSubject subject = context.GetAuthSubject();
            return audit.WriteAsync(new AuditEvent
            {
                Timestamp = clock.UtcNow,
                Category = AuditCategory.Admin,
                Outcome = AuditOutcome.Success,
                SubjectId = subject.Id,
                SubjectName = subject.Name,
                ClientId = subject.ClientId,
                Resource = resource,
                Action = action,
                Detail = detail,
                RemoteIp = context.Connection.RemoteIpAddress?.ToString(),
            }, context.RequestAborted);
        }

        // ---------------------------------------------------------------- 配置与当前主体

        private static IResult GetConfig(HttpContext context)
        {
            CyaimAuthAdminOptions options = context.RequestServices
                .GetRequiredService<IOptions<CyaimAuthAdminOptions>>().Value;
            return Ok(new
            {
                tokenEndpoint = options.TokenEndpoint,
                clientId = options.ClientId,
                serverName = options.ServerName,
            });
        }

        private static async Task<IResult> GetMe(HttpContext context)
        {
            AuthSubject subject = context.GetAuthSubject();
            IPermissionEvaluator evaluator = context.RequestServices.GetRequiredService<IPermissionEvaluator>();
            CancellationToken ct = context.RequestAborted;

            bool read = await evaluator.IsGrantedAsync(subject, AdminPermissions.Read, ct);
            bool manageUsers = await evaluator.IsGrantedAsync(subject, AdminPermissions.ManageUsers, ct);
            bool manageRoles = await evaluator.IsGrantedAsync(subject, AdminPermissions.ManageRoles, ct);
            bool managePermissions = await evaluator.IsGrantedAsync(subject, AdminPermissions.ManagePermissions, ct);
            bool manageClients = await evaluator.IsGrantedAsync(subject, AdminPermissions.ManageClients, ct);
            bool readAudit = await evaluator.IsGrantedAsync(subject, AdminPermissions.ReadAudit, ct);

            return Ok(new
            {
                id = subject.Id,
                name = subject.Name,
                subjectType = subject.SubjectType,
                isAuthenticated = subject.IsAuthenticated,
                roles = subject.Roles,
                clientId = subject.ClientId,
                permissions = new
                {
                    read,
                    manageUsers,
                    manageRoles,
                    managePermissions,
                    manageClients,
                    readAudit,
                },
            });
        }

        // ---------------------------------------------------------------- 仪表盘

        private static async Task<IResult> GetStats(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IServiceProvider sp = context.RequestServices;
            IUserStore userStore = sp.GetRequiredService<IUserStore>();
            IRoleStore roleStore = sp.GetRequiredService<IRoleStore>();
            IClientStore clientStore = sp.GetRequiredService<IClientStore>();
            IPermissionDefinitionStore permissionStore = sp.GetRequiredService<IPermissionDefinitionStore>();
            IAuditLogger audit = sp.GetRequiredService<IAuditLogger>();

            int users = await userStore.CountAsync(null, ct);
            IReadOnlyList<AuthRole> roles = await roleStore.GetAllAsync(ct);
            IReadOnlyList<ClientApplication> clients = await clientStore.GetAllAsync(ct);
            IReadOnlyList<PermissionDefinition> permissions = await permissionStore.GetAllAsync(ct);
            IReadOnlyList<AuditEvent> recentDenied = await audit.QueryAsync(new AuditQuery
            {
                Outcome = AuditOutcome.Denied,
                Take = 10,
            }, ct);

            return Ok(new
            {
                users,
                roles = roles.Count,
                clients = clients.Count,
                permissions = permissions.Count,
                recentDenied,
            });
        }

        // ---------------------------------------------------------------- 用户

        private static async Task<IResult> ListUsers(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IUserStore store = context.RequestServices.GetRequiredService<IUserStore>();
            string? search = context.Request.Query["search"];
            if (string.IsNullOrWhiteSpace(search))
            {
                search = null;
            }
            int skip = ParseInt(context, "skip", 0, 0, int.MaxValue);
            int take = ParseInt(context, "take", 20, 1, 200);

            int total = await store.CountAsync(search, ct);
            IReadOnlyList<AuthUser> items = await store.ListAsync(search, skip, take, ct);
            return Ok(new { total, items = items.Select(UserDto.From).ToArray() });
        }

        private static async Task<IResult> CreateUser(HttpContext context)
        {
            CreateUserRequest? request = await ReadJsonAsync<CreateUserRequest>(context);
            if (request == null || string.IsNullOrWhiteSpace(request.UserName) || string.IsNullOrEmpty(request.Password))
            {
                return Error(StatusCodes.Status400BadRequest, "userName 与 password 为必填项");
            }

            CancellationToken ct = context.RequestAborted;

            // 职责分离：授予角色需 ManageRoles，授予/拒绝权限需 ManagePermissions
            if (request.Roles is { Count: > 0 } &&
                await RequireManageAsync(context, AdminPermissions.ManageRoles, ct) is { } roleDenied)
            {
                return roleDenied;
            }
            if ((request.DirectPermissions is { Count: > 0 } || request.DeniedPermissions is { Count: > 0 }) &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.DirectPermissions, request.DeniedPermissions) is { } invalid)
            {
                return invalid;
            }

            IUserStore store = context.RequestServices.GetRequiredService<IUserStore>();
            IPasswordHasher hasher = context.RequestServices.GetRequiredService<IPasswordHasher>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            var user = new AuthUser
            {
                UserName = request.UserName.Trim(),
                DisplayName = request.DisplayName,
                Email = request.Email,
                PasswordHash = hasher.Hash(request.Password),
                Roles = request.Roles ?? new List<string>(),
                DirectPermissions = request.DirectPermissions ?? new List<string>(),
                DeniedPermissions = request.DeniedPermissions ?? new List<string>(),
                CreatedAt = clock.UtcNow,
                UpdatedAt = clock.UtcNow,
            };

            try
            {
                await store.CreateAsync(user, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status409Conflict, ex.Message);
            }

            await WriteAdminAuditAsync(context, "user/" + user.Id, "create", user.UserName);
            return Created(UserDto.From(user));
        }

        private static async Task<IResult> UpdateUser(HttpContext context, string id)
        {
            UpdateUserRequest? request = await ReadJsonAsync<UpdateUserRequest>(context);
            if (request == null)
            {
                return Error(StatusCodes.Status400BadRequest, "请求体必须为 JSON");
            }

            CancellationToken ct = context.RequestAborted;

            // 职责分离守卫（同 CreateUser）
            if (request.Roles != null &&
                await RequireManageAsync(context, AdminPermissions.ManageRoles, ct) is { } roleDenied)
            {
                return roleDenied;
            }
            if ((request.DirectPermissions != null || request.DeniedPermissions != null) &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.DirectPermissions, request.DeniedPermissions) is { } invalid)
            {
                return invalid;
            }

            IUserStore store = context.RequestServices.GetRequiredService<IUserStore>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            AuthUser? user = await store.FindByIdAsync(id, ct);
            if (user == null)
            {
                return Error(StatusCodes.Status404NotFound, "用户不存在：" + id);
            }

            bool disabling = request.IsEnabled == false && user.IsEnabled;
            bool authzChanged = request.Roles != null || request.DirectPermissions != null || request.DeniedPermissions != null;

            if (request.DisplayName != null)
            {
                user.DisplayName = request.DisplayName;
            }
            if (request.Email != null)
            {
                user.Email = request.Email;
            }
            if (request.Roles != null)
            {
                user.Roles = request.Roles;
            }
            if (request.DirectPermissions != null)
            {
                user.DirectPermissions = request.DirectPermissions;
            }
            if (request.DeniedPermissions != null)
            {
                user.DeniedPermissions = request.DeniedPermissions;
            }
            if (request.IsEnabled.HasValue)
            {
                user.IsEnabled = request.IsEnabled.Value;
            }
            // 授权发生变化或账户被禁用时轮换安全戳，使已签发的访问令牌在下次判断时失效
            if (disabling || authzChanged)
            {
                user.SecurityStamp = Guid.NewGuid().ToString("N");
            }
            user.UpdatedAt = clock.UtcNow;

            try
            {
                await store.UpdateAsync(user, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            if (disabling)
            {
                await RevokeSubjectTokensAsync(context, user.Id, ct);
            }

            await WriteAdminAuditAsync(context, "user/" + user.Id, "update", user.UserName);
            return Ok(UserDto.From(user));
        }

        private static async Task<IResult> ResetUserPassword(HttpContext context, string id)
        {
            ResetPasswordRequest? request = await ReadJsonAsync<ResetPasswordRequest>(context);
            if (request == null || string.IsNullOrEmpty(request.NewPassword))
            {
                return Error(StatusCodes.Status400BadRequest, "newPassword 为必填项");
            }

            CancellationToken ct = context.RequestAborted;
            IUserStore store = context.RequestServices.GetRequiredService<IUserStore>();
            IPasswordHasher hasher = context.RequestServices.GetRequiredService<IPasswordHasher>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            AuthUser? user = await store.FindByIdAsync(id, ct);
            if (user == null)
            {
                return Error(StatusCodes.Status404NotFound, "用户不存在：" + id);
            }

            user.PasswordHash = hasher.Hash(request.NewPassword);
            user.SecurityStamp = Guid.NewGuid().ToString("N");
            user.UpdatedAt = clock.UtcNow;

            try
            {
                await store.UpdateAsync(user, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            // 口令重置后吊销全部刷新令牌：结合安全戳轮换（使旧访问令牌在下次权限判断时失效），
            // 已被盗用的会话无法继续续命。
            await RevokeSubjectTokensAsync(context, user.Id, ct);

            await WriteAdminAuditAsync(context, "user/" + user.Id, "reset-password", user.UserName);
            return Results.NoContent();
        }

        private static async Task<IResult> DeleteUser(HttpContext context, string id)
        {
            CancellationToken ct = context.RequestAborted;
            IUserStore store = context.RequestServices.GetRequiredService<IUserStore>();

            AuthUser? user = await store.FindByIdAsync(id, ct);
            if (user == null)
            {
                return Error(StatusCodes.Status404NotFound, "用户不存在：" + id);
            }

            try
            {
                await store.DeleteAsync(id, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await RevokeSubjectTokensAsync(context, id, ct);

            await WriteAdminAuditAsync(context, "user/" + id, "delete", user.UserName);
            return Results.NoContent();
        }

        // ---------------------------------------------------------------- 角色

        private static async Task<IResult> ListRoles(HttpContext context)
        {
            IRoleStore store = context.RequestServices.GetRequiredService<IRoleStore>();
            IReadOnlyList<AuthRole> roles = await store.GetAllAsync(context.RequestAborted);
            return Ok(roles);
        }

        private static async Task<IResult> CreateRole(HttpContext context)
        {
            RoleRequest? request = await ReadJsonAsync<RoleRequest>(context);
            if (request == null || string.IsNullOrWhiteSpace(request.Name))
            {
                return Error(StatusCodes.Status400BadRequest, "name 为必填项");
            }

            CancellationToken ct = context.RequestAborted;
            // 职责分离：为角色授予权限等同于分发权限，需 ManagePermissions（否则仅持 ManageRoles
            // 者可建立含 auth.admin.** 的角色再自赋而纵向越权）
            if ((request.Permissions is { Count: > 0 } || request.DeniedPermissions is { Count: > 0 }) &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.Permissions, request.DeniedPermissions) is { } invalid)
            {
                return invalid;
            }

            IRoleStore store = context.RequestServices.GetRequiredService<IRoleStore>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            var role = new AuthRole
            {
                Name = request.Name.Trim(),
                DisplayName = request.DisplayName,
                Description = request.Description,
                ParentRoles = request.ParentRoles ?? new List<string>(),
                Permissions = request.Permissions ?? new List<string>(),
                DeniedPermissions = request.DeniedPermissions ?? new List<string>(),
                // IsSystem 仅由种子/迁移设定，不经管理 API 变更（防止制造不可删除角色或绕过系统角色保护）
                IsSystem = false,
                CreatedAt = clock.UtcNow,
                UpdatedAt = clock.UtcNow,
            };

            try
            {
                await store.CreateAsync(role, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status409Conflict, ex.Message);
            }

            await WriteAdminAuditAsync(context, "role/" + role.Id, "create", role.Name);
            return Created(role);
        }

        private static async Task<IResult> UpdateRole(HttpContext context, string id)
        {
            RoleRequest? request = await ReadJsonAsync<RoleRequest>(context);
            if (request == null)
            {
                return Error(StatusCodes.Status400BadRequest, "请求体必须为 JSON");
            }

            CancellationToken ct = context.RequestAborted;
            if ((request.Permissions != null || request.DeniedPermissions != null) &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.Permissions, request.DeniedPermissions) is { } invalid)
            {
                return invalid;
            }

            IRoleStore store = context.RequestServices.GetRequiredService<IRoleStore>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            AuthRole? role = await store.FindByIdAsync(id, ct);
            if (role == null)
            {
                return Error(StatusCodes.Status404NotFound, "角色不存在：" + id);
            }

            if (!string.IsNullOrWhiteSpace(request.Name))
            {
                role.Name = request.Name.Trim();
            }
            if (request.DisplayName != null)
            {
                role.DisplayName = request.DisplayName;
            }
            if (request.Description != null)
            {
                role.Description = request.Description;
            }
            if (request.ParentRoles != null)
            {
                role.ParentRoles = request.ParentRoles;
            }
            if (request.Permissions != null)
            {
                role.Permissions = request.Permissions;
            }
            if (request.DeniedPermissions != null)
            {
                role.DeniedPermissions = request.DeniedPermissions;
            }
            // 不允许经管理 API 修改 IsSystem：否则可把系统角色改为非系统再删除，绕过删除保护
            role.UpdatedAt = clock.UtcNow;

            try
            {
                await store.UpdateAsync(role, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await WriteAdminAuditAsync(context, "role/" + role.Id, "update", role.Name);
            return Ok(role);
        }

        private static async Task<IResult> DeleteRole(HttpContext context, string id)
        {
            CancellationToken ct = context.RequestAborted;
            IRoleStore store = context.RequestServices.GetRequiredService<IRoleStore>();

            AuthRole? role = await store.FindByIdAsync(id, ct);
            if (role == null)
            {
                return Error(StatusCodes.Status404NotFound, "角色不存在：" + id);
            }

            try
            {
                await store.DeleteAsync(id, ct);
            }
            catch (InvalidOperationException ex)
            {
                // 系统内置角色不可删除等存储层约束
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await WriteAdminAuditAsync(context, "role/" + id, "delete", role.Name);
            return Results.NoContent();
        }

        // ---------------------------------------------------------------- 权限定义

        private static async Task<IResult> ListPermissions(HttpContext context)
        {
            IPermissionDefinitionStore store = context.RequestServices.GetRequiredService<IPermissionDefinitionStore>();
            IReadOnlyList<PermissionDefinition> definitions = await store.GetAllAsync(context.RequestAborted);
            return Ok(definitions);
        }

        private static async Task<IResult> UpsertPermissions(HttpContext context)
        {
            List<PermissionUpsertRequest>? request = await ReadJsonAsync<List<PermissionUpsertRequest>>(context);
            if (request == null || request.Count == 0)
            {
                return Error(StatusCodes.Status400BadRequest, "请求体必须为非空 JSON 数组");
            }

            CancellationToken ct = context.RequestAborted;
            IPermissionDefinitionStore store = context.RequestServices.GetRequiredService<IPermissionDefinitionStore>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            var definitions = new List<PermissionDefinition>(request.Count);
            foreach (PermissionUpsertRequest item in request)
            {
                if (string.IsNullOrWhiteSpace(item.Code))
                {
                    return Error(StatusCodes.Status400BadRequest, "每项的 code 为必填项");
                }
                if (!PermissionCode.TryNormalize(item.Code, out string normalized, out string? error))
                {
                    return Error(StatusCodes.Status400BadRequest, $"权限代码非法：{item.Code}（{error}）");
                }
                definitions.Add(new PermissionDefinition
                {
                    Code = normalized,
                    DisplayName = item.DisplayName,
                    Description = item.Description,
                    Group = item.Group,
                    Origin = PermissionOrigin.Manual,
                    CreatedAt = clock.UtcNow,
                });
            }

            await store.UpsertAsync(definitions, ct);
            await WriteAdminAuditAsync(context, "permission", "create",
                string.Join(",", definitions.Select(d => d.Code)));
            return Ok(definitions);
        }

        private static async Task<IResult> DeletePermission(HttpContext context, string code)
        {
            CancellationToken ct = context.RequestAborted;
            IPermissionDefinitionStore store = context.RequestServices.GetRequiredService<IPermissionDefinitionStore>();

            string key = PermissionCode.TryNormalize(code, out string normalized)
                ? normalized
                : code;
            try
            {
                await store.DeleteAsync(key, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await WriteAdminAuditAsync(context, "permission/" + key, "delete");
            return Results.NoContent();
        }

        // ---------------------------------------------------------------- 客户端

        private static async Task<IResult> ListClients(HttpContext context)
        {
            IClientStore store = context.RequestServices.GetRequiredService<IClientStore>();
            IReadOnlyList<ClientApplication> clients = await store.GetAllAsync(context.RequestAborted);
            return Ok(clients.Select(ClientDto.From).ToArray());
        }

        private static async Task<IResult> CreateClient(HttpContext context)
        {
            ClientRequest? request = await ReadJsonAsync<ClientRequest>(context);
            if (request == null || string.IsNullOrWhiteSpace(request.ClientId))
            {
                return Error(StatusCodes.Status400BadRequest, "clientId 为必填项");
            }

            CancellationToken ct = context.RequestAborted;
            // 职责分离：客户端凭据模式下 client.Permissions 会直接授予令牌主体，等同分发权限，
            // 需 ManagePermissions（否则仅持 ManageClients 者可建 auth.admin.** 客户端换令牌越权）
            if (request.Permissions is { Count: > 0 } &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.Permissions) is { } invalidCode)
            {
                return invalidCode;
            }

            IClientStore store = context.RequestServices.GetRequiredService<IClientStore>();
            IPasswordHasher hasher = context.RequestServices.GetRequiredService<IPasswordHasher>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            var client = new ClientApplication
            {
                ClientId = request.ClientId.Trim(),
                ClientName = request.ClientName,
                ClientSecretHash = string.IsNullOrEmpty(request.Secret) ? null : hasher.Hash(request.Secret),
                AllowedGrantTypes = request.AllowedGrantTypes ?? new List<string>(),
                RedirectUris = request.RedirectUris ?? new List<string>(),
                PostLogoutRedirectUris = request.PostLogoutRedirectUris ?? new List<string>(),
                AllowedScopes = request.AllowedScopes ?? new List<string>(),
                Permissions = request.Permissions ?? new List<string>(),
                RequirePkce = request.RequirePkce ?? true,
                AllowOfflineAccess = request.AllowOfflineAccess ?? false,
                Enabled = request.Enabled ?? true,
                AllowedCorsOrigins = request.AllowedCorsOrigins ?? new List<string>(),
                CreatedAt = clock.UtcNow,
                UpdatedAt = clock.UtcNow,
            };
            if (request.AccessTokenLifetimeSeconds.HasValue)
            {
                client.AccessTokenLifetimeSeconds = request.AccessTokenLifetimeSeconds.Value;
            }
            if (request.RefreshTokenLifetimeSeconds.HasValue)
            {
                client.RefreshTokenLifetimeSeconds = request.RefreshTokenLifetimeSeconds.Value;
            }
            if (request.AuthorizationCodeLifetimeSeconds.HasValue)
            {
                client.AuthorizationCodeLifetimeSeconds = request.AuthorizationCodeLifetimeSeconds.Value;
            }

            try
            {
                await store.CreateAsync(client, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status409Conflict, ex.Message);
            }

            await WriteAdminAuditAsync(context, "client/" + client.ClientId, "create", client.ClientName);
            return Created(ClientDto.From(client));
        }

        private static async Task<IResult> UpdateClient(HttpContext context, string id)
        {
            ClientRequest? request = await ReadJsonAsync<ClientRequest>(context);
            if (request == null)
            {
                return Error(StatusCodes.Status400BadRequest, "请求体必须为 JSON");
            }

            CancellationToken ct = context.RequestAborted;
            if (request.Permissions != null &&
                await RequireManageAsync(context, AdminPermissions.ManagePermissions, ct) is { } permDenied)
            {
                return permDenied;
            }
            if (ValidatePermissionCodes(request.Permissions) is { } invalidCode)
            {
                return invalidCode;
            }

            IClientStore store = context.RequestServices.GetRequiredService<IClientStore>();
            IPasswordHasher hasher = context.RequestServices.GetRequiredService<IPasswordHasher>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            ClientApplication? client = await store.FindByClientIdAsync(id, ct);
            if (client == null)
            {
                return Error(StatusCodes.Status404NotFound, "客户端不存在：" + id);
            }

            if (request.ClientName != null)
            {
                client.ClientName = request.ClientName;
            }
            // secret 语义：null=不变，空串=清除，有值=更新
            if (request.Secret != null)
            {
                client.ClientSecretHash = request.Secret.Length == 0 ? null : hasher.Hash(request.Secret);
            }
            if (request.AllowedGrantTypes != null)
            {
                client.AllowedGrantTypes = request.AllowedGrantTypes;
            }
            if (request.RedirectUris != null)
            {
                client.RedirectUris = request.RedirectUris;
            }
            if (request.PostLogoutRedirectUris != null)
            {
                client.PostLogoutRedirectUris = request.PostLogoutRedirectUris;
            }
            if (request.AllowedScopes != null)
            {
                client.AllowedScopes = request.AllowedScopes;
            }
            if (request.Permissions != null)
            {
                client.Permissions = request.Permissions;
            }
            if (request.RequirePkce.HasValue)
            {
                client.RequirePkce = request.RequirePkce.Value;
            }
            if (request.AllowOfflineAccess.HasValue)
            {
                client.AllowOfflineAccess = request.AllowOfflineAccess.Value;
            }
            if (request.AccessTokenLifetimeSeconds.HasValue)
            {
                client.AccessTokenLifetimeSeconds = request.AccessTokenLifetimeSeconds.Value;
            }
            if (request.RefreshTokenLifetimeSeconds.HasValue)
            {
                client.RefreshTokenLifetimeSeconds = request.RefreshTokenLifetimeSeconds.Value;
            }
            if (request.AuthorizationCodeLifetimeSeconds.HasValue)
            {
                client.AuthorizationCodeLifetimeSeconds = request.AuthorizationCodeLifetimeSeconds.Value;
            }
            if (request.Enabled.HasValue)
            {
                client.Enabled = request.Enabled.Value;
            }
            if (request.AllowedCorsOrigins != null)
            {
                client.AllowedCorsOrigins = request.AllowedCorsOrigins;
            }
            client.UpdatedAt = clock.UtcNow;

            try
            {
                await store.UpdateAsync(client, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await WriteAdminAuditAsync(context, "client/" + client.ClientId, "update", client.ClientName);
            return Ok(ClientDto.From(client));
        }

        private static async Task<IResult> RegenerateClientSecret(HttpContext context, string id)
        {
            CancellationToken ct = context.RequestAborted;
            IClientStore store = context.RequestServices.GetRequiredService<IClientStore>();
            IPasswordHasher hasher = context.RequestServices.GetRequiredService<IPasswordHasher>();
            IAuthClock clock = context.RequestServices.GetRequiredService<IAuthClock>();

            ClientApplication? client = await store.FindByClientIdAsync(id, ct);
            if (client == null)
            {
                return Error(StatusCodes.Status404NotFound, "客户端不存在：" + id);
            }

            // 32 字节加密安全随机密钥，明文仅在本次响应返回一次
            string secret = TokenHasher.CreateToken();
            client.ClientSecretHash = hasher.Hash(secret);
            client.UpdatedAt = clock.UtcNow;

            try
            {
                await store.UpdateAsync(client, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            await WriteAdminAuditAsync(context, "client/" + client.ClientId, "regenerate-secret");
            return Ok(new { secret });
        }

        private static async Task<IResult> DeleteClient(HttpContext context, string id)
        {
            CancellationToken ct = context.RequestAborted;
            IClientStore store = context.RequestServices.GetRequiredService<IClientStore>();

            ClientApplication? client = await store.FindByClientIdAsync(id, ct);
            if (client == null)
            {
                return Error(StatusCodes.Status404NotFound, "客户端不存在：" + id);
            }

            try
            {
                await store.DeleteAsync(id, ct);
            }
            catch (InvalidOperationException ex)
            {
                return Error(StatusCodes.Status400BadRequest, ex.Message);
            }

            // 吊销该客户端已签发的全部刷新令牌，避免删除后仍可续期
            var tokenStore = context.RequestServices.GetService<ITokenStore>();
            if (tokenStore != null)
            {
                await tokenStore.RevokeClientRefreshTokensAsync(id, ct);
            }

            await WriteAdminAuditAsync(context, "client/" + id, "delete", client.ClientName);
            return Results.NoContent();
        }

        // ---------------------------------------------------------------- 审计

        private static async Task<IResult> QueryAudit(HttpContext context)
        {
            CancellationToken ct = context.RequestAborted;
            IAuditLogger audit = context.RequestServices.GetRequiredService<IAuditLogger>();

            var query = new AuditQuery
            {
                Skip = ParseInt(context, "skip", 0, 0, int.MaxValue),
                Take = ParseInt(context, "take", 50, 1, 1000),
            };

            string? categoryRaw = context.Request.Query["category"];
            if (!string.IsNullOrWhiteSpace(categoryRaw) && Enum.TryParse(categoryRaw, true, out AuditCategory category))
            {
                query.Category = category;
            }
            string? outcomeRaw = context.Request.Query["outcome"];
            if (!string.IsNullOrWhiteSpace(outcomeRaw) && Enum.TryParse(outcomeRaw, true, out AuditOutcome outcome))
            {
                query.Outcome = outcome;
            }
            string? subjectId = context.Request.Query["subjectId"];
            if (!string.IsNullOrWhiteSpace(subjectId))
            {
                query.SubjectId = subjectId;
            }
            string? fromRaw = context.Request.Query["from"];
            if (!string.IsNullOrWhiteSpace(fromRaw) && DateTimeOffset.TryParse(fromRaw, out DateTimeOffset from))
            {
                query.From = from;
            }
            string? toRaw = context.Request.Query["to"];
            if (!string.IsNullOrWhiteSpace(toRaw) && DateTimeOffset.TryParse(toRaw, out DateTimeOffset to))
            {
                query.To = to;
            }

            IReadOnlyList<AuditEvent> items = await audit.QueryAsync(query, ct);
            return Ok(new { items });
        }
    }
}
