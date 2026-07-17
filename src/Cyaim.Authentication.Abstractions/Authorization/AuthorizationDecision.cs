using Cyaim.Authentication.Abstractions.Permissions;

namespace Cyaim.Authentication.Abstractions.Authorization
{
    /// <summary>
    /// 权限判断结论，含可诊断的原因。
    /// </summary>
    public sealed class AuthorizationDecision
    {
        /// <summary>是否放行</summary>
        public bool IsGranted { get; }

        /// <summary>命中的效果</summary>
        public PermissionEffect Effect { get; }

        /// <summary>结论原因</summary>
        public AuthorizationReason Reason { get; }

        /// <summary>判断的权限代码</summary>
        public string? PermissionCode { get; }

        /// <summary>判断的策略名（ABAC）</summary>
        public string? PolicyName { get; }

        private AuthorizationDecision(bool isGranted, PermissionEffect effect, AuthorizationReason reason, string? permissionCode, string? policyName)
        {
            IsGranted = isGranted;
            Effect = effect;
            Reason = reason;
            PermissionCode = permissionCode;
            PolicyName = policyName;
        }

        /// <summary>创建放行结论</summary>
        public static AuthorizationDecision Granted(AuthorizationReason reason, string? permissionCode = null, string? policyName = null) =>
            new AuthorizationDecision(true, PermissionEffect.Allow, reason, permissionCode, policyName);

        /// <summary>创建拒绝结论</summary>
        public static AuthorizationDecision Denied(AuthorizationReason reason, string? permissionCode = null, string? policyName = null) =>
            new AuthorizationDecision(false, PermissionEffect.Deny, reason, permissionCode, policyName);

        /// <inheritdoc/>
        public override string ToString() =>
            $"{(IsGranted ? "Granted" : "Denied")}({Reason}{(PermissionCode == null ? string.Empty : ", " + PermissionCode)})";
    }

    /// <summary>
    /// 判断结论原因。
    /// </summary>
    public enum AuthorizationReason
    {
        /// <summary>命中允许规则</summary>
        Granted = 0,
        /// <summary>策略评估通过</summary>
        GrantedByPolicy = 1,
        /// <summary>端点未要求权限</summary>
        NotProtected = 2,
        /// <summary>允许游客访问</summary>
        GuestAllowed = 3,
        /// <summary>未命中任何授权规则</summary>
        NoMatchingGrant = 10,
        /// <summary>命中拒绝规则</summary>
        DeniedByRule = 11,
        /// <summary>未认证且端点不允许游客</summary>
        GuestNotAllowed = 12,
        /// <summary>主体被禁用或锁定</summary>
        SubjectDisabled = 13,
        /// <summary>策略评估未通过</summary>
        PolicyNotSatisfied = 14,
        /// <summary>策略不存在</summary>
        PolicyNotFound = 15,
        /// <summary>权限代码非法</summary>
        InvalidPermissionCode = 16,
        /// <summary>凭据无效或过期</summary>
        InvalidCredential = 17,
    }
}
