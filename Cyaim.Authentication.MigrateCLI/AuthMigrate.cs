using Cyaim.Authentication.MigrateCLI.DataBaseProviders.Dapper;
using System;
using System.Collections.Generic;
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
            var npgsqlDapperHelper = NpgsqlDapperHelper.Helper(connectionString);
            //npgsqlDapperHelper.Execute();
        }

        /// <summary>
        /// 使用指定程序集初始化权限节点
        /// </summary>
        /// <param name="assembly"></param>
        public static void InitAccessEndPointData(Assembly assembly, string connectionString)
        {
            using var npgsqlDapperHelper = NpgsqlDapperHelper.Helper(connectionString);


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
