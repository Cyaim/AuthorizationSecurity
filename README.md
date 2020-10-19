# AuthorizationSecurity

> Base ASP.NET Core MVC Endpoint authorization framework

## Quick Start

1,In "Startup.cs" -> "ConfigureServices" Method,the method last add code. 

```C#
services.ConfigureAuth(x =>
            {
                x.SourceLocation = ParameterLocation.Header;
                x.PreAccessEndPointKey = "Sys";
            });
```

2,Go to controller  
In need of authorization Controller or Action mark:
```C#
[AuthEndPoint()]
```
In not authorization Action mark:
```C#
[AuthEndPoint(allowGuest: true)]
```

3,Use Attribute Complate,Run you project~

## Persistence and cache
1,You need a class verify authorization  
Here operation PostgreSQL and redis, You can replace it with something you like.
```C#
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;

using static Cyaim.Authentication.Infrastructure.Helpers.URLStructHelper;

 public class Auth
    {

        static Auth()
        {
            _npgsqlDapperHelper = NpgsqlDapperHelper.Helper("Your databse connection string");
            _redisHelper = new RedisHelper("Your redis connection string", "Auth", 0);
        }

        private readonly static NpgsqlDapperHelper _npgsqlDapperHelper;
        private readonly static RedisHelper _redisHelper;
        const string ROUTE = "/api/v1/{controller}/{action}";

        public static async Task<AuthEndPointAttribute[]> GetAuthEndPointByUser(string authKey, HttpContext httpContext, AuthOptions authOptions)
        {
            string personId = GetUserIdByRedis(authKey);
            if (personId == null)
            {
                personId = "sys_guest";
            }

            URLStruct urlStruct = GetUrlStruct(ROUTE, httpContext.Request.Path); ;

            // Adopt request URL search watching endpoint
            var watchep = authOptions.WatchAuthEndPoint.FirstOrDefault(x =>
            x.Routes != null &&
            x.ControllerName?.ToLower() == urlStruct.Controller.ToLower() + "controller" &&
            x.Routes.Any(r => r.Template?.ToLower() == urlStruct.Action?.ToLower()));
            if (watchep == null)
            {
                //This means that the request is not listening
                //goto GoNonAccess;
                Console.WriteLine($@"Endpoint -> {httpContext.Request.Path} not databse watching range.");
                goto NonAccessWatch;
            }

            if(user permission==false)
            {
                goto GoNonAccess;
            }

            return new AuthEndPointAttribute[1] { watchep };

            //return auths.ToArray();
            //Non Access
            GoNonAccess: return new AuthEndPointAttribute[0];
            //Non watching range
            NonAccessWatch: return null;
        }


        /// <summary>
        /// From redis get token
        /// </summary>
        /// <param name="authKey"></param>
        public static string GetUserIdByRedis(string authKey)
        {
            var personId = _redisHelper.StringGet(authKey);

            return personId;
        }
    }
```

2,Add Auth Handler
In "Startup.cs" -> "ConfigureServices" Method,the method last add code. 

```C#
services.ConfigureAuth(x =>
            {
                x.SourceLocation = ParameterLocation.Header;
                x.ExtractDatabaseAuthEndPoints = new AuthOptions.ExtractAuthEndPointsHandler(Auth.GetAuthEndPointByUser);
                x.PreAccessEndPointKey = "Sys";
            });
```
