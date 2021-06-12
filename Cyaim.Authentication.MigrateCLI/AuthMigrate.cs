using Cyaim.Authentication.Infrastructure;
using Cyaim.Authentication.Infrastructure.Attributes;
using Cyaim.Authentication.MigrateCLI.DataBaseProviders;
using Cyaim.Authentication.MigrateCLI.DataBaseProviders.Dapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Cyaim.Authentication.MigrateCLI
{
    public class AuthMigrate
    {



        /// <summary>
        /// 初始化默认权限表
        /// </summary>
        /// <param name="initType">指定数据库</param>
        /// <param name="connectionString">连接字符串</param>
        public static void InitAccessDataTable(DataStorageType initType, string connectionString)
        {
            switch (initType)
            {
                case DataStorageType.PostgreSQL:
                    {
                        using var npgsqlDapperHelper = NpgsqlDapperHelper.Helper(connectionString);
                        npgsqlDapperHelper.Execute(PostgreSQL.CREATESQL);

                        break;
                    }
                case DataStorageType.MySQL:
                    break;
                case DataStorageType.SQLServer:
                    break;
                default:
                    break;
            }

        }

        /// <summary>
        /// 使用指定程序集初始化权限节点
        /// </summary>
        /// <param name="assembly"></param>
        /// <param name="connectionString"></param>
        /// <param name="appId"></param>
        /// <param name="preAccessEndPointKey"></param>
        public static void InitAccessEndPointData(Assembly assembly, string connectionString, string appId, string preAccessEndPointKey)
        {
            using var npgsqlDapperHelper = NpgsqlDapperHelper.Helper(connectionString);

            //加载授权节点
            IEnumerable<AuthEndPointAttribute> authEndPointParms = new AuthEndPointAttribute[0];
            string assemblyName = assembly.FullName.Split()[0]?.Trim(',') + ".Controllers";
            var types = assembly.GetTypes().Where(x => !x.IsNestedPrivate && x.FullName.StartsWith(assemblyName)).ToList();
            foreach (var item in types)
            {
                var accessParm = AuthServiceCollectionExtensions.GetClassAccessParm_AuthEndPointAttribute(item);
                authEndPointParms = authEndPointParms.Union(accessParm);
                foreach (AuthEndPointAttribute parmItem in accessParm)
                {
                    if (parmItem == null)
                    {
                        continue;
                    }

                    if (string.IsNullOrEmpty(parmItem.AuthEndPoint))
                    {
                        parmItem.AuthEndPoint = $"{preAccessEndPointKey}:{parmItem.ControllerName}.{parmItem.ActionName}";
                    }

                    Console.WriteLine($"加载成功 -> {parmItem.AuthEndPoint}");
                }

            }

            foreach (var item in authEndPointParms)
            {
                var https = item.Routes.Select(x => x.HttpMethods).SelectMany((x, y) => x).Select(x => x.ToUpper());
                int httpMethod = 0;
                foreach (var method in https)
                {
                    HttpMethod.HttpMethodMaps.TryGetValue(method, out int val);
                    httpMethod |= val;
                }

                npgsqlDapperHelper.Execute(@$"INSERT INTO ""Sys_Access"" (""Id"",""AccessCode"",""AppId"",""RequestMethod"") VALUES('{Guid.NewGuid().ToString("N")}','{item.AuthEndPoint}','{(appId == null ? string.Empty : appId)}','{httpMethod}')");
            }

        }

        public enum DataStorageType
        {
            PostgreSQL,
            MySQL,
            SQLServer,
            //...

        }
    }
}
