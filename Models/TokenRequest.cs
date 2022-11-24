namespace okta.Models
{
    public class TokenRequest
    {
        public string? AuthCode { get; set; }
        public string? RefreshToken { get; set; }
    }
}
