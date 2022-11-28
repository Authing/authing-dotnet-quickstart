using System;
using Authing.ApiClient.Domain.Client.Impl.AuthenticationClient;
using Authing.ApiClient.Types;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Opw.HttpExceptions.AspNetCore;
using quickstart.Utils;
using NetDevPack.Security.JwtExtensions;

namespace quickstart
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            // dotnet add package NetDevPack.Security.Jwt
            // services.AddJwksManager(o =>
            //     {
            //         o.Jws = JwsAlgorithm.RS256;
            //     });

            services.AddControllers();

            services.AddMvc().AddHttpExceptions();

            //启用内存缓存(该步骤需在AddSession()调用前使用)
            services.AddDistributedMemoryCache();//启用session之前必须先添加内存
                                                 //services.AddSession();
            services.AddSession(options =>
            {
                options.Cookie.Name = "This.Session";
                options.IdleTimeout = TimeSpan.FromSeconds(2000);//设置session的过期时间
                options.Cookie.HttpOnly = true;//设置在浏览器不能通过js获得该cookie的值
                options.Cookie.IsEssential = true;
            });

            var authenticationClient = new AuthenticationClient(options =>
            {
                options.AppId = Configuration["Authing.Config:AppId"];
                options.AppHost = Configuration["Authing.Config:AppHost"];
                options.RedirectUri = Configuration["Authing.Config:RedirectUri"];
                options.Secret = Configuration["Authing.Config:Secret"];
            });

            services.AddSingleton(typeof(AuthenticationClient), authenticationClient);
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "quickstart", Version = "v1" });
            });

            //由于初始化的时候我们就需要用，所以使用Bind的方式读取配置
            //将配置绑定到JwtSettings实例中
            var jwtSettings = new JwtSettings();
            Configuration.Bind("JwtSettings", jwtSettings);

            // var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            //     // .well-known/oauth-authorization-server or .well-known/openid-configuration
            //     "https://1409458062aaa.authing.cn/oidc/.well-known/openid-configuration",
            //     new OpenIdConnectConfigurationRetriever(),
            //     new HttpDocumentRetriever()
            // );

            // var discoveryDocument = await configurationManager.GetConfigurationAsync();
            // var signingKeys = discoveryDocument.SigningKeys;

            services.AddAuthentication(options =>
            {
                //认证middleware配置
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                //主要是jwt  token参数设置
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    //Token颁发机构
                    ValidIssuer = jwtSettings.Issuer,
                    //颁发给谁
                    ValidAudience = jwtSettings.Audience,
                    //这里的key要进行加密，需要引用Microsoft.IdentityModel.Tokens
                    // IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                    // ValidateIssuerSigningKey = true,
                    //是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
                    // ValidateLifetime = true,
                    //允许的服务器时间偏移量
                    // ClockSkew = TimeSpan.Zero,
                    ValidAlgorithms = new string[] { "RS256" },
                    // IssuerSigningKeys = signingKeys,
                };
                o.RequireHttpsMetadata = false;
                o.SaveToken = false;
                o.IncludeErrorDetails = true;
                o.SetJwksOptions(new JwkOptions(jwtSettings.JwksUri, jwtSettings.Issuer, new TimeSpan(TimeSpan.TicksPerDay)));
            });

            services.AddAuthorization(options =>
                {
                    options.AddPolicy(
                        "WeatherForecast:read",
                        policy => policy.RequireClaim("scope", "WeatherForecast:read"));
                }
            );

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            app.UseHttpExceptions();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "quickstart v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
