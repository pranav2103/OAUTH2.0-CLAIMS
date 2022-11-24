namespace okta.Models
{
    public class JWTAccessToken
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public int? ExpiresIn { get; set; }
        public string ? Id_Token { get; set; }
    }
}
