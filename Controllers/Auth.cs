using System;
using System.Threading.Tasks;
using Authing.ApiClient.Auth;
using Authing.ApiClient.Auth.Types;
using Authing.ApiClient.Types;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
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

        // private readonly IJsonWebKeySetService _jwksService;
        // IJsonWebKeySetService jwksService

        public AuthController(AuthenticationClient authenticationClient, IConfiguration configuration)
        {
            _authenticationClient = authenticationClient;
            _configuration = configuration;
            // _jwksService = jwksService;
        }

        private Boolean ValidateToken(string jwt)
        {
            var handler = new JsonWebTokenHandler();
            var currentIssuer = $"https://应用域名.authing.cn/oidc";

            var result = handler.ValidateToken(jwt,
                new TokenValidationParameters
                {
                    ValidIssuer = currentIssuer,
                    // SigningCredentials = _keyService.GetCurrentSigningCredentials()
                    // AudienceValidator = new AudienceValidator(new string []{"audiences"}, );
                });
            return result.IsValid;
        }

        [HttpGet]
        [Route("login")]
        public string GetLoginUrl()
        {
            var oauthOption = new OidcOption
            {
                AppId = _configuration["Authing.Config:AppId"],
                RedirectUri = _configuration["Authing.Config:RedirectUri"],
                State = "state",
            };
            var loginUri = _authenticationClient.BuildAuthorizeUrl(oauthOption);
            return loginUri;
        }

        [HttpGet]
        [Route("callback")]
        public async Task<object> HandleCallback([FromQuery] string Code)
        {
            if (Code == null)
            {
                return new BadRequestException("code 无效");
            }
            CodeToTokenRes tokenInfo;
            try
            {
                tokenInfo = await _authenticationClient.GetAccessTokenByCode(Code);
            }
            catch (Exception)
            {
                throw new BadRequestException("code 无效");
            }
            var token = tokenInfo.AccessToken;
            UserInfo userInfo;
            try
            {
                userInfo = await _authenticationClient.GetUserInfoByAccessToken(token);
                userInfo.Token = token;
            }
            catch (Exception)
            {
                throw new BadRequestException("token 无效"); ;
            }
            HttpContext.Session.Set("user", userInfo);
            var _userInfo = HttpContext.Session.Get<UserInfo>("user");
            Console.WriteLine(_userInfo);
            return Redirect("/auth/profile");
        }

        [HttpGet]
        [Route("logout")]
        public RedirectResult GetLogoutUrl()
        {
            var url = _authenticationClient.BuildLogoutUrl(new LogoutParams
            {
                Expert = true,
                IdToken = HttpContext.Session.Get<User>("user")?.Token,
                RedirectUri = "http://localhost:5000",
            });
            HttpContext.Session.Clear();
            return Redirect(url);
        }

        [HttpGet]
        [Route("profile")]
        [Produces("application/json")]
        public object GetUserInfo()
        {

            if (HttpContext.Session.Get<UserInfo>("user") != null)
            {
                var userInfo = HttpContext.Session.Get<UserInfo>("user");
                return userInfo;
            }
            return Redirect("/auth/login");
        }
    }
}
