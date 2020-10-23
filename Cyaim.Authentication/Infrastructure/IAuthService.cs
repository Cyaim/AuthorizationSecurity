using Cyaim.Authentication.Infrastructure.Attributes;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace Cyaim.Authentication.Infrastructure
{
    public interface IAuthService
    {

        /// <summary>
        /// 注册节点
        /// </summary>
        void RegisterAccessCode(string accessCode, bool isAccept);



        #region 校验授权

        /// <summary>
        /// 校验默认授权，特性
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        bool CheckAuthDefault(HttpContext context);

        #endregion

        #region 获取授权凭据

        /// <summary>
        /// 获取授权凭据
        /// </summary>
        /// <param name="http">http上下文</param>
        /// <returns></returns>
        string GetAuthorizationValue(HttpContext http);

        /// <summary>
        /// 检验凭据
        /// </summary>
        /// <returns></returns>
         Task<bool> CheckAuthorization(HttpContext context);

        /// <summary>
        /// 从Header搜索凭据
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string GetAuthHeader(HttpContext context, string key);

        /// <summary>
        /// 从Cookie搜索凭据
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string GetAuthCookie(HttpContext context, string key);

        /// <summary>
        /// 从Query搜索凭据
        /// </summary>
        /// <param name="context"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        string GetAuthQuery(HttpContext context, string key);

        #endregion

    }
}