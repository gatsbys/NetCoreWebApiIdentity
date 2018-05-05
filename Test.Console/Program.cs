using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Test.Console
{
    //Note: First you should run the `ASPNETCore2JwtAuthentication.WebApp` project and then run the `ConsoleClient` project.

    public class Token
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }

    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    class Program
    {
        private static readonly string _baseAddress = "http://localhost:5001/"; // Your port here
        private static readonly HttpClientHandler _httpClientHandler = new HttpClientHandler
        {
            UseCookies = true,
            UseDefaultCredentials = true,
            CookieContainer = new CookieContainer()
        };
        private static readonly HttpClient _httpClient = new HttpClient(_httpClientHandler)
        {
            BaseAddress = new Uri(_baseAddress)
        };

        public static async Task Main(string[] args)
        {
            await CreateRoleAsync("/api/manage", "Admin");

            var option = System.Console.ReadLine();
            Token token = null;
            while (option != "exit")
            {
                switch (option)
                {
                    case "createuser":
                        await CreateAsync(requestUri: "/api/accounts",
                            email: "email@email.com",
                            password: "Password1_");
                        break;
                    case "login":
                        token = (await LoginAsync(requestUri: "/api/auth/login",
                            email: "email@email.com",
                            password: "Password1_")).Token;
                        break;
                    case "refresh":
                        token = await RefreshTokenAsync("/api/auth/refreshtoken", token, GetAntiforgeryCookies());
                        break;
                    case "secured":
                        await CallProtectedApiAsync("/api/secured", token);
                        break;
                    case "full":
                        await CreateAsync(requestUri: "/api/accounts",
                            email: "email@email.com",
                            password: "Password1_");
                        token = (await LoginAsync(requestUri: "/api/auth/login",
                            email: "email@email.com",
                            password: "Password1_")).Token;
                        await CallProtectedApiAsync("/api/securedresource", token);
                        break;
                }
                option = System.Console.ReadLine();
            }
        }

        private static Dictionary<string, string> GetAntiforgeryCookies()
        {
            System.Console.WriteLine("\nGet Antiforgery Cookies:");
            var cookies = _httpClientHandler.CookieContainer.GetCookies(new Uri(_baseAddress));

            var appCookies = new Dictionary<string, string>();
            System.Console.WriteLine("WebApp Cookies:");
            foreach (Cookie cookie in cookies)
            {
                System.Console.WriteLine($"Name : {cookie.Name}");
                System.Console.WriteLine($"Value: {cookie.Value}");
                appCookies.Add(cookie.Name, cookie.Value);
            }
            return appCookies;
        }

        private static async Task<(Token Token, Dictionary<string, string> AppCookies)> LoginAsync(string requestUri, string email, string password)
        {
            System.Console.WriteLine("\nLogin:");

            var response = await _httpClient.PostAsJsonAsync(
                 requestUri,
                 new { Email = email, Password = password });
            response.EnsureSuccessStatusCode();

            var token = await response.Content.ReadAsAsync<Token>(new[] { new JsonMediaTypeFormatter() });
            System.Console.WriteLine($"Response    : {response}");
            System.Console.WriteLine($"AccessToken : {token.AccessToken}");
            System.Console.WriteLine($"RefreshToken: {token.RefreshToken}");

            var appCookies = GetAntiforgeryCookies();
            return (token, appCookies);
        }


        private static async Task<(Token Token, Dictionary<string, string> AppCookies)> CreateAsync(string requestUri, string email, string password)
        {
            try
            {
                System.Console.WriteLine("\nLogin:");

                var response = await _httpClient.PostAsJsonAsync(
                    requestUri,
                    new { Username = email, Email = email, Name = "Cristian", Surname = "de Murcia", Password = password });
                response.EnsureSuccessStatusCode();

                var token = await response.Content.ReadAsAsync<Token>(new[] { new JsonMediaTypeFormatter() });
                System.Console.WriteLine($"Response    : {response}");
                System.Console.WriteLine($"AccessToken : {token.AccessToken}");
                System.Console.WriteLine($"RefreshToken: {token.RefreshToken}");

                var appCookies = GetAntiforgeryCookies();
                return (token, appCookies);
            }
            catch (Exception ex)
            {
                System.Console.WriteLine(ex);
            }
            return (null, null);
        }

        private static async Task CreateRoleAsync(string requestUri, string role)
        {
            try
            {
                System.Console.WriteLine($"Creating role {role}");

                var response = await _httpClient.PostAsJsonAsync(
                    requestUri,
                    role);
                response.EnsureSuccessStatusCode();

                System.Console.WriteLine($"Created role {role}");

            }
            catch (Exception ex)
            {
                System.Console.WriteLine(ex);
            }
        }

        private static async Task<Token> RefreshTokenAsync(string requestUri, Token token, Dictionary<string, string> appCookies)
        {
            System.Console.WriteLine("\nRefreshToken:");

            if (!_httpClient.DefaultRequestHeaders.Contains("X-XSRF-TOKEN"))
            {
                // this is necessary for [AutoValidateAntiforgeryTokenAttribute] and all of the 'POST' requests
                _httpClient.DefaultRequestHeaders.Add("X-XSRF-TOKEN", appCookies["XSRF-TOKEN"]);
            }
            // this is necessary to populate the this.HttpContext.User object automatically
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
            var response = await _httpClient.PostAsJsonAsync(
                 requestUri,
                 new { refreshToken = token.RefreshToken });
            response.EnsureSuccessStatusCode();

            var newToken = await response.Content.ReadAsAsync<Token>(new[] { new JsonMediaTypeFormatter() });
            System.Console.WriteLine($"Response    : {response}");
            System.Console.WriteLine($"New AccessToken : {newToken.AccessToken}");
            System.Console.WriteLine($"New RefreshToken: {newToken.RefreshToken}");
            return newToken;
        }

        private static async Task CallProtectedApiAsync(string requestUri, Token token)
        {
            System.Console.WriteLine("\nCall ProtectedApi:");
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
            var response = await _httpClient.GetAsync(requestUri);
            var message = await response.Content.ReadAsStringAsync();
            System.Console.WriteLine("URL response: " + message);
        }
    }
}
