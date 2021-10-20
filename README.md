# 安装依赖

运行以下命令安装项目依赖：

```bash
$ dotnet restore
```

# 填写你的应用配置

在 appsettings.Development.json 中，修改配置为你的应用配置：

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  // .Net Core Web App 快速开始
  "Authing.Config": {
    "AppId": "APP_ID",
    "Secret": "APP_SECRET",
    "AppHost": "https://{你的域名}.authing.cn",
    "RedirectUri": "http://localhost:8000/auth/callback"
  },
  // .Net Core Web API Server 快速开始
  "JwtSettings": {
    // "Issuer": "https://{你的域名}.authing.cn/oidc",
    // "Audience": "60b847b52cd547f747a4cfe8",
    // "JwksUri": "https://{你的域名}.authing.cn/oidc/.well-known/jwks"
  }
}
```

# 运行

运行本示例程序：

```bash
$ dotnet run
```

# 参考文档

[.Net Core Web App 快速开始](https://docs.authing.cn/v2/quickstarts/webApp/csharpDotNetCore.html)
[.Net Core Web API Server 快速开始](https://docs.authing.cn/v2/quickstarts/apiServer/csharpDotNetCore/)