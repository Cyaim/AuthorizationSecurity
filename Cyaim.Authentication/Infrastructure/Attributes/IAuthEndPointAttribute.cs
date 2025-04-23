using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.Infrastructure.Attributes
{
    /// <summary>
    /// 权限节点特性
    /// </summary>
    public interface IAuthEndPointAttribute : IAuthMetadata
    {
        /// <summary>
        /// 权限节点
        /// </summary>
        string AuthEndPoint { get; set; }

        /// <summary>
        /// 是否允许访问
        /// </summary>
        bool IsAllow { get; set; }



    }
}
