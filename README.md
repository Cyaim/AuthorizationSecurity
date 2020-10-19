# AuthorizationSecurity

> Base ASP.NET Core MVC Endpoint authorization framework

## Quick Start

1,In "Startup.cs" -> "ConfigureServices" Method,the method last add code. 

```C#
services.ConfigureAuth(x =>
            {
                x.SourceLocation = ParameterLocation.Header;
                x.ExtractDatabaseAuthEndPoints = new AuthOptions.ExtractAuthEndPointsHandler(Auth.GetAuthEndPointByUser);
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

## Persistence and cache
