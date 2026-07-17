using Cyaim.Authentication.Abstractions;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Minimal API 权限标注扩展。
    /// </summary>
    public static class CyaimAuthEndpointConventionExtensions
    {
        /// <summary>
        /// 要求访问该端点具备指定权限（任一满足）。
        /// <code>app.MapGet("/users", ...).RequirePermission("sys.user.read");</code>
        /// </summary>
        public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, params string[] permissionCodes)
            where TBuilder : IEndpointConventionBuilder
        {
            builder.Add(b => b.Metadata.Add(new RequirePermissionAttribute(permissionCodes)));
            return builder;
        }

        /// <summary>
        /// 要求访问该端点具备全部指定权限。
        /// </summary>
        public static TBuilder RequireAllPermissions<TBuilder>(this TBuilder builder, params string[] permissionCodes)
            where TBuilder : IEndpointConventionBuilder
        {
            builder.Add(b => b.Metadata.Add(new RequirePermissionAttribute(permissionCodes) { RequireAll = true }));
            return builder;
        }

        /// <summary>
        /// 要求访问该端点满足命名 ABAC 策略。
        /// </summary>
        public static TBuilder RequireAuthPolicy<TBuilder>(this TBuilder builder, string policyName)
            where TBuilder : IEndpointConventionBuilder
        {
            builder.Add(b => b.Metadata.Add(new RequirePermissionAttribute() { Policy = policyName }));
            return builder;
        }

        /// <summary>
        /// 允许游客访问该端点（覆盖 ProtectAllEndpoints）。
        /// </summary>
        public static TBuilder AllowGuest<TBuilder>(this TBuilder builder)
            where TBuilder : IEndpointConventionBuilder
        {
            builder.Add(b => b.Metadata.Add(new AllowGuestAttribute()));
            return builder;
        }
    }
}
