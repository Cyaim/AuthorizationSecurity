using Microsoft.AspNetCore.Mvc.Routing;
using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.Infrastructure.Attributes
{
    /// <summary>
    /// 授权节点特性
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class AuthEndPointAttribute : Attribute, IAuthEndPointAttribute
    {
        /// <inheritdoc/>
        public AuthEndPointAttribute(string authEndPoint, bool allowGuest = false) : this(authEndPoint: authEndPoint, isAllow: true, allowGuest: allowGuest)
        {

        }

        /// <inheritdoc/>
        public AuthEndPointAttribute(bool isAllow, bool allowGuest = false) : this(authEndPoint: null, isAllow: isAllow, allowGuest: allowGuest)
        {

        }

        /// <summary>
        /// 标记权限节点，由系统生成权限节点名称（ControllerName.ActionName）
        /// </summary>
        public AuthEndPointAttribute() : this(authEndPoint: null, isAllow: true, allowGuest: false)
        {

        }

        /// <summary>
        /// 标记权限节点
        /// </summary>
        /// <param name="authEndPoint">权限节点名称</param>
        /// <param name="isAllow">是否允许访问,true允许/false拒绝</param>
        /// <param name="allowGuest">是否允许游客访问,true允许/false拒绝</param>
        public AuthEndPointAttribute(string authEndPoint, bool isAllow, bool allowGuest)
        {
            AuthEndPoint = authEndPoint;
            IsAllow = isAllow;
            AllowGuest = allowGuest;
        }

        /// <summary>
        /// 权限节点
        /// </summary>
        public string AuthEndPoint { get; set; }

        /// <summary>
        /// 是否允许访问
        /// </summary>
        public bool IsAllow { get; set; } = true;

        /// <summary>
        /// 是否允许游客访问
        /// </summary>
        public bool AllowGuest { get; set; }

        /// <summary>
        /// 节点Controller
        /// </summary>
        public string ControllerName { get; set; }

        /// <summary>
        /// 节点Action
        /// </summary>
        public string ActionName { get; set; }

        /// <summary>
        /// Action名称是否可空，标记方法不填写访问路径时为true
        /// </summary>
        public bool ActionCanEmpty { get; set; }

        /// <summary>
        /// 请求方法
        /// </summary>
        public HttpMethodAttribute[] Routes { get; set; }
    }
}
