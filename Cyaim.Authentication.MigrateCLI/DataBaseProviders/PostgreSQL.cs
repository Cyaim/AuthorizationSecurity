using System;
using System.Collections.Generic;
using System.Text;

namespace Cyaim.Authentication.MigrateCLI.DataBaseProviders
{
    public class PostgreSQL
    {
        public const string CREATESQL = @"
            -- ----------------------------
            -- Sequence structure for sys_access_groups_id_seq
            -- ----------------------------
            DROP SEQUENCE IF EXISTS ""public"".""sys_access_groups_id_seq"";
            CREATE SEQUENCE ""public"".""sys_access_groups_id_seq"" 
            INCREMENT 1
            MINVALUE  1
            MAXVALUE 9223372036854775807
            START 1
            CACHE 1;

            -- ----------------------------
            -- Table structure for Sys_Access
            -- ----------------------------
            DROP TABLE IF EXISTS ""public"".""Sys_Access"";
            CREATE TABLE ""public"".""Sys_Access"" (
              ""Id"" varchar(32) COLLATE ""pg_catalog"".""default"" NOT NULL,
              ""AccessCode"" varchar(255) COLLATE ""pg_catalog"".""default"" NOT NULL,
              ""AppId"" int8,
              ""RequestMethod"" int2,
              ""Remark"" varchar(255) COLLATE ""pg_catalog"".""default""
            )
            ;
            COMMENT ON COLUMN ""public"".""Sys_Access"".""Id"" IS '系统权限列表';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""AccessCode"" IS '权限代码';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""AppId"" IS '应用ID';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""RequestMethod"" IS '请求方法，
            多个方法进行或运算存值
            Get 2、POST 4、DELETE 8、PUT 16、PATCH 32';
            COMMENT ON COLUMN ""public"".""Sys_Access"".""Remark"" IS '权限描述';

            -- ----------------------------
            -- Table structure for Sys_Access_GroupUser_Map
            -- ----------------------------
            DROP TABLE IF EXISTS ""public"".""Sys_Access_GroupUser_Map"";
            CREATE TABLE ""public"".""Sys_Access_GroupUser_Map"" (
              ""Id"" varchar(32) COLLATE ""pg_catalog"".""default"" NOT NULL,
              ""UserId"" varchar(255) COLLATE ""pg_catalog"".""default"",
              ""GroupId"" int8
            )
            ;
            COMMENT ON COLUMN ""public"".""Sys_Access_GroupUser_Map"".""Id"" IS '用户与权限组映射表
            ';
            COMMENT ON COLUMN ""public"".""Sys_Access_GroupUser_Map"".""UserId"" IS '用户ID';
            COMMENT ON COLUMN ""public"".""Sys_Access_GroupUser_Map"".""GroupId"" IS '权限组名称';

            -- ----------------------------
            -- Table structure for Sys_Access_Groups
            -- ----------------------------
            DROP TABLE IF EXISTS ""public"".""Sys_Access_Groups"";
            CREATE TABLE ""public"".""Sys_Access_Groups"" (
              ""Id"" int8 NOT NULL DEFAULT nextval('sys_access_groups_id_seq'::regclass),
              ""GroupName"" varchar(255) COLLATE ""pg_catalog"".""default"",
              ""Remark"" varchar(255) COLLATE ""pg_catalog"".""default"",
              ""CreateDate"" timestamp(0)
            )
            ;
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups"".""Id"" IS '系统权限组表';
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups"".""GroupName"" IS '权限组名';
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups"".""Remark"" IS '备注';

            -- ----------------------------
            -- Table structure for Sys_Access_Groups_Accept
            -- ----------------------------
            DROP TABLE IF EXISTS ""public"".""Sys_Access_Groups_Accept"";
            CREATE TABLE ""public"".""Sys_Access_Groups_Accept"" (
              ""Id"" varchar(32) COLLATE ""pg_catalog"".""default"" NOT NULL,
              ""SysAccessGroupId"" int8,
              ""AccessCode"" varchar(255) COLLATE ""pg_catalog"".""default"",
              ""AllowGuest"" bool
            )
            ;
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups_Accept"".""Id"" IS '权限组权限列表';
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups_Accept"".""SysAccessGroupId"" IS '权限组ID';
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups_Accept"".""AccessCode"" IS '权限代码';
            COMMENT ON COLUMN ""public"".""Sys_Access_Groups_Accept"".""AllowGuest"" IS '是否允许游客访问';

            -- ----------------------------
            -- Primary Key structure for table Sys_Access
            -- ----------------------------
            ALTER TABLE ""public"".""Sys_Access"" ADD CONSTRAINT ""Sys_Access_pkey"" PRIMARY KEY (""Id"");

            -- ----------------------------
            -- Primary Key structure for table Sys_Access_GroupUser_Map
            -- ----------------------------
            ALTER TABLE ""public"".""Sys_Access_GroupUser_Map"" ADD CONSTRAINT ""Sys_Access_GroupUser_Map_pkey"" PRIMARY KEY (""Id"");

            -- ----------------------------
            -- Primary Key structure for table Sys_Access_Groups
            -- ----------------------------
            ALTER TABLE ""public"".""Sys_Access_Groups"" ADD CONSTRAINT ""Sys_Access_Group_pkey"" PRIMARY KEY (""Id"");

            -- ----------------------------
            -- Primary Key structure for table Sys_Access_Groups_Accept
            -- ----------------------------
            ALTER TABLE ""public"".""Sys_Access_Groups_Accept"" ADD CONSTRAINT ""Sys_Access_Groups_Accept_pkey"" PRIMARY KEY (""Id"");
        ";

    }
}
