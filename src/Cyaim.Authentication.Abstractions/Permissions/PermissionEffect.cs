namespace Cyaim.Authentication.Abstractions.Permissions
{
    /// <summary>
    /// 权限判断结果效果。拒绝优先（Deny-Override）：同一代码同时命中允许与拒绝时结果为拒绝。
    /// </summary>
    public enum PermissionEffect
    {
        /// <summary>未命中任何授权规则</summary>
        NotSet = 0,
        /// <summary>允许</summary>
        Allow = 1,
        /// <summary>拒绝</summary>
        Deny = 2,
    }
}
