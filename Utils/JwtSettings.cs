namespace quickstart.Utils
{
    public class JwtSettings
    {
        //token是谁颁发的
        public string Issuer { get; set; }
        //token可以给哪些客户端使用
        public string Audience { get; set; }
        //加密的key
        public string SecretKey { get; set; }
        // JwksUri
        public string JwksUri { get; set; }
    }
}