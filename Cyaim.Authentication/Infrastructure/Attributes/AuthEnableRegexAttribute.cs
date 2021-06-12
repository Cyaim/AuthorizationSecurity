using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Cyaim.Authentication.Infrastructure.Attributes
{
    /// <summary>
    /// 标志启用正则匹配，该特性只能标记在控制器层
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = true)]
    public class AuthEnableRegexAttribute : Attribute, IAuthEndPointAttribute
    {
        /// <summary>
        /// 标记可用正则的权限节点
        /// </summary>
        /// <param name="authEndPoint">权限节点名称</param>
        /// <param name="isAllow">是否允许访问,true允许/false拒绝</param>
        /// <param name="allowGuest">是否允许游客访问,true允许/false拒绝</param>
        public AuthEnableRegexAttribute(string authEndPoint, bool isAllow, bool allowGuest)
        {
            AuthEndPoint = authEndPoint;
            IsAllow = isAllow;
            AllowGuest = allowGuest;
        }

        /// <inheritdoc/>
        public AuthEnableRegexAttribute(string authEndPoint, bool isAllow = true) : this(authEndPoint, isAllow, false) { }


        /// <summary>
        /// 权限节点，可包含正则字符串
        /// </summary>
        public string AuthEndPoint { get; set; }

        /// <summary>
        /// 是否允许访问
        /// </summary>
        public bool IsAllow { get; set; }

        /// <summary>
        /// 是否允许游客访问
        /// </summary>
        public bool AllowGuest { get; set; }

        /// <summary>
        /// 正则表达式
        /// </summary>
        public Regex Regex { get; set; }
    }
}
