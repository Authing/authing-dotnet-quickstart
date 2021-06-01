using System;
using System.Threading.Tasks;
using Authing.ApiClient.Auth;
using Authing.ApiClient.Auth.Types;
using Authing.ApiClient.Types;
using Authing.ApiClient.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace quickstart.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthenticationClient _authenticationClient;
        // private readonly IJsonWebKeySetService _jwksService;
        // IJsonWebKeySetService jwksService

        public AuthController(AuthenticationClient authenticationClient)
        {
            _authenticationClient = authenticationClient;
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
            var oauthOption = new OauthOption
            {
                AppId = "AppId",
                RedirectUri = "RedirectUri",
                ResponseType = OauthResponseType.CODE,
                State = "state",
                // Scope = "",
            };
            var loginUri = _authenticationClient.BuildAuthorizeUrl(oauthOption);
            return loginUri;
        }

        [HttpGet]
        [Route("callback")]
        public async Task<RedirectResult> HandleCallback([FromQuery] string Code)
        {
            string token = "";
            if (!string.IsNullOrEmpty(Code))
            {
                var tokenInfo = (await _authenticationClient.GetAccessTokenByCode(Code)).Convert<CodeToTokenRes>();
                token = tokenInfo.AccessToken;
            }
            var userInfo = (await _authenticationClient.GetUserInfoByAccessToken(token)).Convert<User>();
            HttpContext.Session.Set("user", userInfo);
            return Redirect("/");
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
        public object GetUserInfo()
        {
            if (HttpContext.Session.Get<User>("user") != null)
            {
                return Redirect("/login");
            }
            return HttpContext.Session.Get<User>("user");
        }
    }
}
