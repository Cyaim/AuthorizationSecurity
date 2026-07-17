using System;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Threading;
using Dapper;
using Npgsql;

namespace Cyaim.Authentication.MigrateCLI.DataBaseProviders.Dapper
{
    public class NpgsqlDapperHelper : BaseDapperFactory, IDisposable
    {
        public NpgsqlDapperHelper()
            : base()
        { }

        /// <summary>
        /// 构建实例并创建NpgsqlConnection传递给基类
        /// </summary>
        /// <param name="connStr"></param>
        public NpgsqlDapperHelper(string connStr)
            : base(new NpgsqlConnection(connStr))
        {
            base._ConnectionString = connStr;
        }

        /// <summary>
        /// 获取helper对象
        /// </summary>
        /// <param name="connectionString"></param>
        /// <returns></returns>
        public static NpgsqlDapperHelper Helper(string connectionString)
        {
            var dbHelper = new NpgsqlDapperHelper();
            dbHelper._ConnectionString = connectionString;

            dbHelper.DbConnection = new NpgsqlConnection(dbHelper._ConnectionString);
            //dbHelper._DBConnection = new MySqlConnection(dbHelper._ConnectionString);
            return dbHelper;
        }

    }
}
