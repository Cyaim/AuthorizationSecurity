using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.MigrateCLI.DataBaseProviders
{
    public class PostgreSQL
    {
        public const string CREATESQL = @"
            -- ----------------------------
            -- Table structure for Sys_Access
            -- ----------------------------
            DROP TABLE IF EXISTS ""public"".""Sys_Access"";
                    CREATE TABLE ""public"".""Sys_Access"" (
              ""Id"" varchar(32) COLLATE ""pg_catalog"".""default"" NOT NULL,
              ""AccessCode"" varchar(255) COLLATE ""pg_catalog"".""default"",
              ""URI"" varchar(3000) COLLATE ""pg_catalog"".""default"",
              ""AppId"" int8,
              ""RequestMethod"" int2
            )
            ;
            COMMENT ON COLUMN ""public"".""Sys_Access"".""Id"" IS '系统权限列表';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""AccessCode"" IS '权限代码';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""URI"" IS 'URI访问路径';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""AppId"" IS '应用ID';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""RequestMethod"" IS '请求方法，
            多个方法进行或运算存值
            Get 2、POST 4、DELETE 8、PUT 16、PATCH 32';

            -- ----------------------------
            -- Primary Key structure for table Sys_Access
            -- ----------------------------
            ALTER TABLE ""public"".""Sys_Access"" ADD CONSTRAINT ""Sys_Access_pkey"" PRIMARY KEY(""Id"");";

    }
}
