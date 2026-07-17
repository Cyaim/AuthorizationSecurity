using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Dapper;

namespace Cyaim.Authentication.MigrateCLI.DataBaseProviders.Dapper
{
    public abstract class BaseDapperFactory : IDisposable
    {
        protected string _ErrorMessage { get; set; }
        protected bool _HasError { get; set; }

        protected string _ConnectionString = string.Empty;
        public virtual string ConnectionString { get { return this._ConnectionString; } }

        protected IDbConnection DbConnection { get; set; }

        /// <summary>
        /// if value is true, will throw the exception, otherwise, suppress the exception
        /// </summary>
        public bool ThrowException { get; set; }

        public bool CheckError()
        {
            return this._HasError;
        }

        public string GetErrorMessage()
        {
            return this._ErrorMessage;
        }

        protected BaseDapperFactory() { }

        protected BaseDapperFactory(IDbConnection dbConnection)
        {
            DbConnection = dbConnection;
        }

        public T QueryFirstOrDefault<T>(string query, DynamicParameters dynamicParameters)
        {
            T obj = default(T);

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                obj = DbConnection.QueryFirstOrDefault<T>(query, dynamicParameters);
            };

            Retry(action);

            return obj;
        }

        public List<T> Query<T>(string query, DynamicParameters dynamicParameters)
        {
            List<T> list = null;

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                list = DbConnection.Query<T>(query, dynamicParameters).ToList();
            };

            Retry(action);

            return list;
        }

        public List<T> Query<T>(string query)
        {
            List<T> list = null;

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                list = DbConnection.Query<T>(query).ToList();
            };

            Retry(action);

            return list;
        }

        public virtual T InsertWithReturn<T>(string query, DynamicParameters dynamicParameters)
        {
            T returnValue = default(T);

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                returnValue = DbConnection.ExecuteScalar<T>(query, dynamicParameters);
            };

            Retry(action);

            return returnValue;
        }

        public virtual T InsertWithReturn<T>(string query)
        {
            T returnValue = default(T);

            Action action = () =>
            {
                returnValue = DbConnection.ExecuteScalar<T>(query);
            };

            Retry(action);

            return returnValue;
        }

        public int Execute(string query, DynamicParameters dynamicParameters)
        {
            int affectedCounter = 0;
            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                affectedCounter = DbConnection.Execute(query, dynamicParameters);
            };

            Retry(action);

            return affectedCounter;
        }


        public bool Any(string query, DynamicParameters dynamicParameters)
        {
            int count = 0;
            Action action = () =>
            {
                count = (int)DbConnection.ExecuteScalar(query, dynamicParameters);
            };

            Retry(action);

            return count > 0;
        }
        public object SelAny(string query, DynamicParameters dynamicParameters)
        {
            object count = 0;
            Action action = () =>
            {
                count = (int)DbConnection.ExecuteScalar(query, dynamicParameters);
            };

            Retry(action);

            return count;
        }

        public int Execute(string query)
        {
            int affectedCounter = 0;
            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                affectedCounter = DbConnection.Execute(query, null);
            };

            Retry(action);

            return affectedCounter;
        }

        public int Execute<T>(string query, List<T> entities)
        {
            int affectedCounter = 0;

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                affectedCounter = DbConnection.Execute(query, entities);
            };

            Retry(action);

            return affectedCounter;
        }

        public T ExecuteScalar<T>(string query, DynamicParameters dynamicParameters)
        {
            T scalarValue = default(T);

            Action action = () =>
            {
                //_DBConnection.IsInUse = true;
                scalarValue = DbConnection.ExecuteScalar<T>(query, dynamicParameters);
            };

            Retry(action);

            return scalarValue;
        }

        protected virtual void Retry(Action action)
        {
            int retryCounter = 0;

            while (true)
            {
                try
                {
                    action();
                    this._HasError = false;
                    this._ErrorMessage = string.Empty;
                    return;
                }
                catch (SqlException ex)
                {
                    if (!Enum.IsDefined(typeof(RetryableSqlErrors), ex.Number))
                    {
                        HandlerException(ex);

                        if (ThrowException)
                            throw ex;
                        else
                            break;
                    }

                    retryCounter++;
                    if (retryCounter > MAX_RETRY)
                    {
                        HandlerException(ex);

                        if (ThrowException)
                            throw ex;
                        else
                            break;
                    }

                    Thread.Sleep(ex.Number == (int)RetryableSqlErrors.SqlTimeout ? longWait : shortWait);
                    continue;
                }
                catch (Exception ex)
                {
                    HandlerException(ex);

                    if (ThrowException)
                        throw ex;
                    else
                        break;
                }
            }

        }


        protected void HandlerException(Exception exception)
        {
            System.Diagnostics.Debug.WriteLine(exception);
            this._HasError = true;
            this._ErrorMessage = Convert.ToString(exception);
        }

        public void Dispose()
        {
            if (DbConnection == null)
                return;

            if (DbConnection.State != ConnectionState.Closed)
                DbConnection.Close();


            DbConnection.Dispose();
            DbConnection = null;
            GC.SuppressFinalize(this);
        }

        protected enum RetryableSqlErrors
        {
            SqlConnectionBroken = -1,
            SqlTimeout = -2,
            SqlOutOfMemory = 701,
            SqlOutOfLocks = 1204,
            SqlDeadlockVictim = 1205,
            SqlLockRequestTimeout = 1222,
            SqlTimeoutWaitingForMemoryResource = 8645,
            SqlLowMemoryCondition = 8651,
            SqlWordbreakerTimeout = 30053
        }

        #region setting

        //http://stackoverflow.com/questions/4821668/what-is-good-c-sharp-coding-style-for-catching-sqlexception-and-retrying
        protected const int MAX_RETRY = 5;

        protected const double LONG_WAIT_SECONDS = 5;
        protected const double SHORT_WAIT_SECONDS = 0.5;
        protected static readonly TimeSpan longWait = TimeSpan.FromSeconds(LONG_WAIT_SECONDS);
        protected static readonly TimeSpan shortWait = TimeSpan.FromSeconds(SHORT_WAIT_SECONDS);

        /// <summary>
        /// Sets a flag on an <see cref="T:System.Exception"/> so that all the stack trace information is preserved
        /// when the exception is re-thrown.
        /// </summary>
        /// <remarks>This is useful because "throw" removes information, such as the original stack frame.</remarks>
        /// <see href="http://weblogs.asp.net/fmarguerie/archive/2008/01/02/rethrowing-exceptions-and-preserving-the-full-call-stack-trace.aspx"/>
        protected static void PreserveStackTrace(Exception ex)
        {
            MethodInfo preserveStackTrace = typeof(Exception).GetMethod("InternalPreserveStackTrace", BindingFlags.Instance | BindingFlags.NonPublic);
            preserveStackTrace.Invoke(ex, null);
        }

        #endregion
    }

    //public class Connection
    //{
    //    public Connection(IDbConnection dbConnection, bool isInUse = false)
    //    {
    //        DbConnection = dbConnection;
    //        IsInUse = isInUse;
    //    }

    //    public IDbConnection DbConnection { get; set; }

    //    public bool IsInUse { get; set; }
    //}

    public static class DapperEx
    {
        /// <summary>
        /// new DynamicParameters().AddEx()
        /// </summary>
        /// <param name="dynamicParameters"></param>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <param name="dbType"></param>
        /// <param name="direction"></param>
        /// <param name="size"></param>
        /// <param name="precision"></param>
        /// <param name="scale"></param>
        /// <returns></returns>
        public static DynamicParameters AddEx(this DynamicParameters dynamicParameters, string name, object value = null, DbType? dbType = null, ParameterDirection? direction = null, int? size = null, byte? precision = null, byte? scale = null)
        {
            if (dynamicParameters == null)
            {
                dynamicParameters = new DynamicParameters();
            }
            dynamicParameters.Add(name, value, dbType, direction, size, precision, scale);
            return dynamicParameters;
        }

        /// <summary>
        /// 构建INSERT字段和格式化模版
        /// Fileds：filed1,filed2
        /// AtValues:@value1,@value2
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static (string Fileds, string AtValues) GetFileds<T>() where T : new()
        {
            T t = new T();
            var type = t.GetType();
            var pros = type.GetProperties();
            StringBuilder sb = new StringBuilder();
            StringBuilder sb2 = new StringBuilder();
            foreach (var item in pros)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append($@"""{item.Name}""");

                    sb2.Append(",@");
                    sb2.Append(item.Name);
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            if (sb2.Length > 0)
            {
                sb2.Remove(0, 1);
            }

            return (sb.ToString(), sb2.ToString());
        }

        /// <summary>
        /// 构建字段模版
        /// 例：value1,value2
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="fields">选择字段</param>
        /// <param name="isExcludeFields">true为排除，false为包含</param>
        /// <returns></returns>
        public static (string Fileds, string AtValues) GetFileds<T>(Func<T, object> fields, bool isExcludeFields = true) where T : new()
        {
            T t = new T();
            var type = t.GetType();
            var pros = type.GetProperties();

            //if (fields == null)
            //{
            //    throw new NullReferenceException("参数{fields}不可为null");
            //}
            object f = null;
            Type type2 = null;
            PropertyInfo[] pros2 = new PropertyInfo[1];
            if (fields != null)
            {
                f = fields(t);
                type2 = f.GetType();
                pros2 = type2.GetProperties();
                var excludeStrs = pros2.Select(x => x.Name);
                pros = pros.Where(x => !excludeStrs.Contains(x.Name)).ToArray();
            }

            StringBuilder sb = new StringBuilder();
            StringBuilder sb2 = new StringBuilder();
            foreach (var item in isExcludeFields ? pros : pros2)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append($@"""{item.Name}""");

                    sb2.Append(",@");
                    sb2.Append(item.Name);
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            if (sb2.Length > 0)
            {
                sb2.Remove(0, 1);
            }

            return (sb.ToString(), sb2.ToString());
        }

        /// <summary>
        /// 未完成
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <param name="fields">查询的字段</param>
        /// <param name="filter">过滤</param>
        /// <param name="isExcludeFields">是否排除fields</param>
        /// <param name="nonEmpty">可否为空</param>
        /// <returns></returns>
        public static (string Fields, string Where, DynamicParameters Parameters) GetFileds<T>(this T t, Func<T, object> fields, Expression<Func<T, bool>> filter, bool isExcludeFields = true, bool nonEmpty = false) where T : new()
        {
            var type = t.GetType();
            var pros = type.GetProperties();

            object f = null;
            Type type2 = null;
            PropertyInfo[] pros2 = new PropertyInfo[1];
            if (fields != null)
            {
                f = fields(t);
                type2 = f.GetType();
                pros2 = type2.GetProperties();
                var excludeStrs = pros2.Select(x => x.Name);
                pros = pros.Where(x => !excludeStrs.Contains(x.Name)).ToArray();
            }

            var lambda = filter.Parameters[0].Name;
            var where = filter.Body.ToString().Replace("AndAlso", "And").Replace("OrElse", "Or").Replace("==", "=").Replace($"{lambda}.", "");
            MatchCollection matches = Regex.Matches(where, @"\([^()]+\)");


            StringBuilder sb = new StringBuilder();
            DynamicParameters parameters = new DynamicParameters();
            foreach (var item in isExcludeFields ? pros : pros2)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append(item.Name);
                    var value = item.GetValue(t);


                    var mathch = (from Match m in matches where m.Value.IndexOf(item.Name) > -1 select m).FirstOrDefault();
                    if (mathch != null)
                    {
                        var v = mathch.Value;

                        if (!(value == null || string.IsNullOrEmpty(value.ToString())) || nonEmpty)
                        {
                            var index = v.IndexOf(" ");
                            var index2 = v.IndexOf(" ", index + 1);
                            var oldStr = v.Substring(index2 + 1, v.IndexOf(")") - 1 - index2);

                            where = where.Replace(v, v.Replace(oldStr, $"@{item.Name}"));

                            parameters.Add(item.Name, value);
                        }
                        else
                        {
                            where = where.Replace(v, "");
                        }
                    }

                }
            }
            matches = Regex.Matches(where, @"\([^()]+\)");
            foreach (var item in isExcludeFields ? pros2 : null)
            {
                if (item.CanRead)
                {


                    var mathch = (from Match m in matches where m.Value.IndexOf(item.Name) > -1 select m).FirstOrDefault();
                    if (mathch != null)
                    {
                        var v = mathch.Value;

                        var index = v.IndexOf(" ");
                        var index2 = v.IndexOf(" ", index + 1);
                        var oldStr = v.Substring(index2 + 1, v.IndexOf(")") - 1 - index2);

                        where = where.Replace(v, "");
                    }

                }
            }
            where = where.Replace(" And ( Or ", "").Replace(" Or ( And ", "");

            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            return (sb.ToString(), where, parameters);
        }

        public static (string Where, DynamicParameters Parameters) GetFileds<T>(this T model, List<FilterBuilder<T>> filters)
        {
            foreach (var item in filters)
            {
                item.Data = model;
            }
            var t = model.GetType();
            var pros = t.GetProperties();
            //获取主键名
            var primaryKeyObj = filters.Where(x => x.IsPrimaryKey).FirstOrDefault();
            var primaryKey = primaryKeyObj?.Name;
            var pkType = primaryKeyObj.Value.GetType();
            if (pkType.IsPrimitive || primaryKey is string || pkType.IsValueType)
            {
                throw new Exception("primaryKeyFunc传参，请使用对象，例如：x=>new{}");
            }

            var pk = pros.Where(x => x.Name == primaryKey).FirstOrDefault();
            if (pk == null)
            {
                throw new Exception("主键不存在");
            }

            var idValue = pk.GetValue(model)?.ToString();

            StringBuilder sb = new StringBuilder();
            DynamicParameters parameters = new DynamicParameters();
            var last = filters.Last();
            foreach (var item in filters)
            {
                //有主键
                if (!string.IsNullOrEmpty(idValue) && item.Name != primaryKey)
                {
                    continue;
                }
                var v = item.Value;

                if (item.IsNonEmpty || v == null || string.IsNullOrEmpty(v.ToString()))
                {
                    continue;
                    //if (v == null || string.IsNullOrEmpty(v.ToString()))
                    //{
                    //    continue;
                    //}
                }


                //第一次的时候再1=1后面添加AND
                if (filters[0] == item)
                {
                    sb.Append(" AND ");
                }
                sb.Append(item.Name);
                sb.Append($"{FilterBuilder<object>.FilterOperatorList[(int)item.OperatorForValue]}@");
                sb.Append(item.Name);
                parameters.Add(item.Name, v);
                if (item == last)
                {
                    break;
                }
                sb.Append(item.OperatorForNext);
            }

            var wheres = sb.ToString().Split(new string[1] { " AND " }, StringSplitOptions.RemoveEmptyEntries).Where(x => !string.IsNullOrEmpty(x)).ToList();
            var where = "1=1";
            if (wheres.Count > 0)
            {
                where = wheres.Aggregate((x, y) => x + " AND " + y);
            }


            return (where, parameters);
        }

        /// <summary>
        /// 构建SELECT查询字段、Where IN值模版
        /// 例如：value1,value2
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <returns></returns>
        public static string GetValues<T>(T t) where T : new()
        {
            var type = t.GetType();
            var pros = type.GetProperties();
            StringBuilder sb = new StringBuilder();
            foreach (var item in pros)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    var v = item.GetValue(t);
                    sb.Append(v == null ? "''" : $"'{v.ToString()}'");
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 按模型构建DynamicParameters
        /// DynamicParameters：name为T中的名称,value为T中属性的值
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <returns></returns>
        public static DynamicParameters GetValuesForDynamicParameters<T>(T t)
        {
            var type = t.GetType();
            var pros = type.GetProperties();
            DynamicParameters parameters = new DynamicParameters();
            foreach (var item in pros)
            {
                if (item.CanRead)
                {
                    var v = item.GetValue(t);
                    var value = v == null ? "" : v;
                    parameters.Add(item.Name, value);
                }
            }
            return parameters;
        }

        /// <summary>
        /// 构建SET字段与值模版
        /// 例如：字段名1=值1,字段名2=值2
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <returns></returns>
        public static string GetFiledsAndValues<T>(T t)
        {
            var type = t.GetType();
            var pros = type.GetProperties();
            StringBuilder sb = new StringBuilder();
            foreach (var item in pros)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append($@"""{item.Name}""");
                    sb.Append("=");
                    var v = item.GetValue(t);
                    sb.Append(v == null ? "''" : $"'{v.ToString()}'");
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 构建SET参数模版与参数对象，T中所有属性，"A"=@A
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <returns></returns>
        public static (string Parameters, DynamicParameters ValueDynamicParameters) GetFiledsAndValuesForDynamicParameters<T>(T t)
        {
            var type = t.GetType();
            var pros = type.GetProperties();
            StringBuilder sb = new StringBuilder();
            DynamicParameters parameters = new DynamicParameters();

            foreach (var item in pros)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append($@"""{item.Name}""");
                    sb.Append("=@");
                    sb.Append(item.Name);

                    var v = item.GetValue(t);
                    var value = v == null ? "" : v;
                    parameters.Add(item.Name, value);
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            return (sb.ToString(), parameters);
        }

        /// <summary>
        /// 构建SET参数模版与参数对象，"A"=@A
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="t"></param>
        /// <param name="fields">需要被构建的字段</param>
        /// <param name="isExcludeFields">true为排除字段</param>
        /// <returns></returns>
        public static (string Parameters, DynamicParameters ValueDynamicParameters) GetFiledsAndValuesForDynamicParameters<T>(T t, Func<T, object> fields, bool isExcludeFields = true)
        {
            //表达式中的字段
            var obj = fields(t);
            if (obj == null)
            {
                throw new NullReferenceException("{fields}不能为null");
            }

            var ty = obj.GetType();
            var exclude = ty.GetProperties();
            var excludeStrs = exclude.Select(x => x.Name);

            //原始类中的字段
            var type = t.GetType();
            var pros = type.GetProperties().Where(x => !excludeStrs.Contains(x.Name));
            StringBuilder sb = new StringBuilder();
            DynamicParameters parameters = new DynamicParameters();

            var useObj = isExcludeFields ? t : obj;
            foreach (var item in isExcludeFields ? pros : exclude)
            {
                if (item.CanRead)
                {
                    sb.Append(",");
                    sb.Append($@"""{item.Name}""");
                    sb.Append("=@");
                    sb.Append(item.Name);

                    var v = item.GetValue(useObj);
                    var value = v == null ? "" : v;
                    parameters.Add(item.Name, value);
                }
            }
            if (sb.Length > 0)
            {
                sb.Remove(0, 1);
            }
            return (sb.ToString(), parameters);
        }
    }

    public class FilterBuilder<T>
    {
        public static readonly List<string> FilterOperatorList = new List<string> { " = ", " <> ", " > ", " >= ", " < ", " <= ", " OR ", " AND ", " Like ", " NOT LIKE " };

        public Func<T, object> Field { get; set; }

        public string Name
        {
            get
            {
                var type = Field(Data).GetType();
                return type.GetProperties().FirstOrDefault().Name;
            }
        }

        public object Value
        {
            get
            {
                if (Data == null)
                {
                    return null;
                }
                return Field(Data);
            }
        }

        public T Data { get; set; }

        /// <summary>
        /// 对值的操作
        /// </summary>
        public FilterOperatorEnum OperatorForValue { get; set; } = FilterOperatorEnum.Eq;

        /// <summary>
        /// 对下个表达式的操作
        /// </summary>
        public FilterOperatorEnum OperatorForNext { get; set; } = FilterOperatorEnum.And;

        /// <summary>
        /// 是否主键
        /// </summary>
        public bool IsPrimaryKey { get; set; }

        /// <summary>
        /// 是否不为空
        /// </summary>
        public bool IsNonEmpty { get; set; } = true;
    }

    public enum FilterOperatorEnum
    {

        //等于
        Eq = 0,
        NotEqual = 1,
        //大于
        Gt = 2,
        Gte = 3,
        //小于
        Lt = 4,
        Lte = 5,
        //或者
        Or = 6,
        //并且
        And = 7,
        Like = 8,
        NotLike = 9
    }

}
