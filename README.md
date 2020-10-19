# AuthorizationSecurity

> Base ASP.NET Core MVC Endpoint authorization framework

## Quick Start

In "Startup.cs" ->"ConfigureServices" Method,the last add code.
`
services.ConfigureAuth(x =>
            {
                x.SourceLocation = ParameterLocation.Header;
                x.ExtractDatabaseAuthEndPoints = new AuthOptions.ExtractAuthEndPointsHandler(Auth.GetAuthEndPointByUser);
                x.PreAccessEndPointKey = "Sys";
            });
`
