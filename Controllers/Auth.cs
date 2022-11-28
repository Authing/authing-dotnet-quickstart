using System;
using System.Text;
using System.Threading.Tasks;
using Authing.ApiClient.Domain.Client.Impl.AuthenticationClient;
using Authing.ApiClient.Domain.Model;
using Authing.ApiClient.Types;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Opw.HttpExceptions;


namespace quickstart.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthenticationClient _authenticationClient;
        private readonly IConfiguration _configuration;

        public AuthController(AuthenticationClient authenticationClient, IConfiguration configuration)
        {
            _authenticationClient = authenticationClient;
            _configuration = configuration;
        }

        /// <summary>
        /// 借助 _authenticationClient 生成登录链接
        /// </summary>
        /// <returns>string</returns>
        [HttpGet]
        [Route("login")]
        public async Task<RedirectResult> GetLoginUrl()
        {
            // 配置 OIDC 相关信息
            var oauthOption = new OidcOption
            {
                AppId = _configuration["Authing.Config:AppId"],
                RedirectUri = _configuration["Authing.Config:RedirectUri"]
            };
            // 生成对应的 loginUrl
            var loginUri = _authenticationClient.BuildAuthorizeUrl(oauthOption);
            return Redirect(loginUri);
        }

        /// <summary>
        /// 处理授权之后的回调，借助 _authenticationClient 将回调得到的 Code 信息换取 Token 信息，之后跳转到 /auth/profile
        /// </summary>
        /// <param name="Code">回调传入的 Code 信息</param>
        /// <returns>Redirect</returns>
        [HttpGet]
        [Route("callback")]
        public async Task<RedirectResult> HandleCallback([FromQuery] string Code)
        {
            // 无效 Code 处理
            
            if (Code == null)
            {
                throw new BadRequestException("code 无效");
            }
            CodeToTokenRes tokenInfo;
            try
            {
                // 错误的 Code 可能会导致换取 Token 失败，出现异常大部分都是 Code 错误的原因
                tokenInfo = await _authenticationClient.GetAccessTokenByCode(Code);
            }
            catch (Exception)
            {
                // 抛出错误处理，传入 Code 有问题
                throw new BadRequestException("code 无效");
            }
            var token = tokenInfo.AccessToken;
            UserInfo userInfo;
            try
            {
                // 通过 Token 获取用户信息，错误的 Token 可能会导致异常
                userInfo = await _authenticationClient.GetUserInfoByAccessToken(token);
                // 将 Token 信息存储到 userInfo 中 
                userInfo.Token = tokenInfo.AccessToken;
            }
            catch (Exception)
            {
                throw new BadRequestException("token 无效"); ;
            }
            // 将 userInfo 存储到 Session 中
            HttpContext.Session.Set("user", userInfo);
            HttpContext.Session.Set("useridtoken", tokenInfo.IdToken);
            return Redirect("/auth/profile");
        }

        /// <summary>
        /// 借助 _authenticationClient 生成用户登出 url，并跳转
        /// </summary>
        /// <returns>RedirectResult</returns>
        [HttpGet]
        [Route("logout")]
        public RedirectResult GetLogoutUrl()
        {
            // 根据配置信息生成登出 url
            var url = _authenticationClient.BuildLogoutUrl(new LogoutParams
            {
                Expert = true,
                IdToken = HttpContext.Session.GetString("useridtoken").Trim('"'),
                // 跳转 url 可以自定义，当用户登出成功时将跳转到这个地址，此处默认为 "http://localhost:5000"
                RedirectUri = "http://localhost:5000/auth/login",
            });
            // 清除 Session 中的用户信息
            HttpContext.Session.Clear();
            return Redirect(url);
        }

        [HttpGet]
        [Route("profile")]
        [Produces("application/json")]
        public object GetUserInfo()
        {
            // 考虑到 userInfo 是存储到 Session 中，如果 Session 中没有 userInfo 则代表用户没有进行登录
            if (HttpContext.Session.Get<UserInfo>("user") != null)
            {
                // 从 Session 中获取 userInfo 并返回
                var userInfo = HttpContext.Session.Get<UserInfo>("user");
                return userInfo;
            }
            // 如果用户没有进行登录，则跳转到 /auth/login 进行登录
            return Redirect("/auth/login");
        }
    }
}
