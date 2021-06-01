using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Authing.ApiClient.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using NetDevPack.Security.JwtSigningCredentials;
using NetDevPack.Security.JwtSigningCredentials.Interfaces;

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
            // services.AddJwksManager();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => false;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            //启用内存缓存(该步骤需在AddSession()调用前使用)
            services.AddDistributedMemoryCache();//启用session之前必须先添加内存
                                                 //services.AddSession();
            services.AddSession(options =>
            {
                options.Cookie.Name = ".AdventureWorks.Session";
                options.IdleTimeout = TimeSpan.FromSeconds(2000);//设置session的过期时间
                options.Cookie.HttpOnly = true;//设置在浏览器不能通过js获得该cookie的值
                options.Cookie.IsEssential = true;
            });

            var authenticationClient = new AuthenticationClient(options =>
            {
                options.AppId = Configuration["Authing.Config:AppId"];
                // options.AppId = Configuration["Authing.Config:AppId"];
                options.Host = Configuration["Authing.Config:AppHost"];
                options.Secret = Configuration["Authing.Config:Secret"];
                options.RedirectUri = Configuration["Authing.Config:RedirectUri"];
            });
            services.AddSingleton(typeof(AuthenticationClient), authenticationClient);
            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "quickstart", Version = "v1" });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "quickstart v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
