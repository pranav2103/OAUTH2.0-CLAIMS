using IdentityModel.Client;
using Microsoft.AspNetCore.Mvc;
using okta.Models;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

using Microsoft.AspNetCore.Cors;

using System.Security.Cryptography.X509Certificates;

using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;

namespace okta.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpGet]
        [Route("GetRedirectUri")]

        public ActionResult GetRedirectUri()
        {
            var config = new ConfigurationBuilder()
                                    .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                                    .AddJsonFile("appsettings.json", false, true)
                                    .Build();
            var scope = HttpUtility.UrlEncode(config["OAuth:scope"]).Replace("+", "%20");
            var authRedirectUri = $"{config["OAuth:idpBaseUrl"]}?client_id={config["OAuth:clientId"]}" +
                $"&redirect_uri={HttpUtility.UrlEncode(config["OAuth:redirectUri"])}" +
                $"&response_type={config["OAuth:responseType"]}&scope={scope}" +
                $"&state={config["OAuth:state"]}";
            if (!string.IsNullOrEmpty(config["OAuth:response_mode"]))
            {
                authRedirectUri = authRedirectUri + $"&{config["OAuth:response_mode"]}";
            }

            if (!string.IsNullOrEmpty(config["OAuth:policyID"]))
            {
                authRedirectUri = authRedirectUri + $"&{config["OAuth:policyID"]}";
            }
            if (!string.IsNullOrEmpty(config["OAuth:prompt"]))
            {
                authRedirectUri = authRedirectUri + $"&{config["OAuth:prompt"]}";
            }


            return Redirect(authRedirectUri);
        }
        private static async Task<JwtSecurityToken> ValidateToken(
           string token,
           string issuer,
           IConfigurationManager<OpenIdConnectConfiguration> configurationManager,
           CancellationToken ct = default(CancellationToken))
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(ct);
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,


                // Allow for some drift in server time
                // (a lower value is better; we recommend two minutes or less)
                ClockSkew = TimeSpan.FromMinutes(2),
                // See additional validation for aud below
            };

            try
            {
                validationParameters.ValidAudience = "0oa43wm0vgZkhEDQU5d7";
                var principal = new JwtSecurityTokenHandler()
                    .ValidateToken(token, validationParameters, out var rawValidatedToken);
                Console.WriteLine("test");
                return (JwtSecurityToken)rawValidatedToken;
            }
            catch (SecurityTokenValidationException)
            {
                // Logging, etc.

                return null;
            }
        }
    [HttpPost]
    
    [Route("ReturnAuthToken")]
    public async Task<IActionResult> ReturnAuthToken([Microsoft.AspNetCore.Mvc.FromBody] Models.TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.RefreshToken) && string.IsNullOrEmpty(request.AuthCode))
        {
            return StatusCode(500, "Auth code or Refresh token missing.");
        }
        using (HttpClient client = new HttpClient())
        {

            HttpResponseMessage? response = null;
            try
            {
                var config = new ConfigurationBuilder()
                                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                                .AddJsonFile("appsettings.json", false, true)
                                .Build();
                string postData = string.Empty;
                var requestUri = config["OAuth:authTokenEndPointV2"];
                var encryptedClientSecret = config["OAuth:applicationSecret"];
                var certificateThumbprint = config["OAuth:certificateThumbprint"];                

                if (config["OAuth:OAuthFlowType"].ToUpper() != "clientCertificate".ToUpper())
                {
                    var clientSecret = new X509CertificateEncryptionProvider(certificateThumbprint).Decrypt(encryptedClientSecret, certificateThumbprint);
                    if (string.IsNullOrEmpty(request.RefreshToken))
                    {
                        postData = $"client_id={config["OAuth:clientId"]}&scope={config["OAuth:scope"]}" +
                            $"&code={request.AuthCode}" +
                            $"&redirect_uri={config["OAuth:redirectUri"]}" +
                            $"&grant_type={config["OAuth:codeGrantType"]}" +
                            $"&client_secret={clientSecret}";
                    }
                    else
                    {
                        postData = $"client_id={config["OAuth:clientId"]}&scope={config["OAuth:scope"]}" +
                            $"&refresh_token={request.RefreshToken}" +
                            $"&redirect_uri={config["OAuth:redirectUri"]}" +
                            $"&grant_type={config["OAuth:refreshTokenGrantType"]}" +
                             $"&client_secret={clientSecret}";
                    }
                }
                else
                {
                    var certificate = GetCertificate(config["OAuth:OAuthClientCertificateThumbprint"]);

                    // header
                    var header = new { alg = "RS256", typ = "JWT", x5t = Base64UrlEncode(certificate.GetCertHash()) };

                    // claimset
                    const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
                    DateTimeOffset validFrom = DateTimeOffset.UtcNow;
                    DateTimeOffset validUntil = validFrom.AddSeconds(JwtToAadLifetimeInSeconds);

                    var claimset = new
                    {
                        iss = config["OAuth:clientId"],
                        sub = config["OAuth:clientId"],
                        aud = config["OAuth:authTokenEndPointV2"],
                        exp = validUntil.ToUnixTimeSeconds(),
                        jti = Guid.NewGuid(),
                        nbf = validFrom.ToUnixTimeSeconds(),
                        iat = validFrom.ToUnixTimeSeconds(),

                    };

                    // encoded header
                    var headerEncoded = ToBase64UrlString(JsonConvert.SerializeObject(header));

                    // encoded claimset
                    var claimsetEncoded = ToBase64UrlString(JsonConvert.SerializeObject(claimset));

                    // input
                    var input = headerEncoded + "." + claimsetEncoded;
                    var inputBytes = Encoding.UTF8.GetBytes(input);

                    // signiture
                    RSA? rsa = certificate.GetRSAPrivateKey();

                    var signatureBytes = rsa.SignData(inputBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var signatureEncoded = ToBase64UrlString(signatureBytes);

                    // jwt
                    var jwt = input + "." + signatureEncoded;
                    if (string.IsNullOrEmpty(request.RefreshToken))
                    {
                        postData = $"client_id={config["OAuth:clientId"]}&scope={config["OAuth:scope"]}" +
                            $"&code={request.AuthCode}" +
                            $"&redirect_uri={config["OAuth:redirectUri"]}" +
                            $"&grant_type={config["OAuth:codeGrantType"]}" +
                            $"&client_assertion_type={HttpUtility.UrlEncode(config["OAuth:clientAssertionType"])}" +
                            $"&client_assertion={jwt}";
                    }
                    else
                    {
                        postData = $"client_id={config["OAuth:clientId"]}&scope={config["OAuth:scope"]}" +
                            $"&refresh_token={request.RefreshToken}" +
                            $"&redirect_uri={config["OAuth:redirectUri"]}" +
                            $"&grant_type={config["OAuth:refreshTokenGrantType"]}" +
                            $"&client_assertion_type={HttpUtility.UrlEncode(config["OAuth:clientAssertionType"])}" +
                            $"&client_assertion={jwt}";

                    }
                }

                // Create POST data and convert it to a byte array.
                var requestTask = await client.SendAsync(new HttpRequestMessage
                {
                    Content = new StringContent(postData, Encoding.UTF8, "application/x-www-form-urlencoded"),
                    Method = HttpMethod.Post,
                    RequestUri = new Uri(requestUri)
                });

                if (requestTask.IsSuccessStatusCode)
                {
                    var result = requestTask.StatusCode == HttpStatusCode.NoContent
                            ? default(JObject)
                            : JsonConvert.DeserializeObject<JObject>(await requestTask.Content.ReadAsStringAsync());

                        var authTokenData = new JWTAccessToken
                        {
                            AccessToken = (string)result["access_token"] ?? string.Empty,
                            RefreshToken = (string)result["refresh_token"] ?? string.Empty,
                            ExpiresIn = (int)result["expires_in"],
                            Id_Token = (string)result["id_token"] ?? string.Empty
                        };
                        var accessCode = authTokenData.AccessToken;
                        var issuer = "https://dev-6152383.okta.com/oauth2/aus43xlhrzaEaZieY5d7";

                        ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("https://dev-6152383.okta.com/oauth2/aus43xlhrzaEaZieY5d7/.well-known/oauth-authorization-server", new OpenIdConnectConfigurationRetriever());
                       await ValidateToken(accessCode, issuer, configManager);
                    return Ok(authTokenData);
                }
                else
                {
                    return StatusCode(500, "Message_NoPermission");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            if (response == null)
            {
                return StatusCode(500, "Message_NoPermission-response null");
            }
            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                return StatusCode(500, "Message_NoPermission-bad request");
            }
            return Ok();
        }
    }

        private static X509Certificate2 GetCertificate(string thumbPrint)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            X509Certificate2Collection certificates = null;
            store.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2 result = null;

                certificates = store.Certificates;

                for (int i = 0; i < certificates.Count; i++)
                {
                    X509Certificate2 cert = certificates[i];

                    if (cert.Thumbprint.ToUpperInvariant() == thumbPrint.ToUpperInvariant())
                    {
                        result = new X509Certificate2(cert);

                        return result;
                    }
                }

                if (result == null)
                {
                    X509Store userStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    userStore.Open(OpenFlags.ReadOnly);
                    certificates = userStore.Certificates;

                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];

                        if (cert.Thumbprint.ToUpperInvariant() == thumbPrint.ToUpperInvariant())
                        {
                            result = new X509Certificate2(cert);

                            return result;
                        }
                    }

                    if (result == null)
                    {
                        throw new Exception(string.Format(System.Globalization.CultureInfo.InvariantCulture, "No certificate was found for thumbprint {0}", thumbPrint));
                    }
                }

                return null;
            }
            finally
            {
                if (certificates != null)
                {
                    for (int i = 0; i < certificates.Count; i++)
                    {
                        X509Certificate2 cert = certificates[i];
                        cert.Reset();
                    }
                }

                store.Close();
            }
        }


        static string ToBase64UrlString(string inputText)
        {
            var bytes = Encoding.UTF8.GetBytes(inputText);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        static string ToBase64UrlString(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static int GetExpiryDate(X509Certificate2 x509Certificate2)
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var currentUtcTime = DateTime.UtcNow;

            var exp = (int)currentUtcTime.AddMinutes(4).Subtract(utc0).TotalSeconds;

            return exp;
        }

        static string Base64UrlEncode(byte[] arg)
        {
            char Base64PadCharacter = '=';
            char Base64Character62 = '+';
            char Base64Character63 = '/';
            char Base64UrlCharacter62 = '-';
            char Base64UrlCharacter63 = '_';

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }

    }


}