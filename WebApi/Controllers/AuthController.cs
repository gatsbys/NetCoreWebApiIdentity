using System.Threading.Tasks;
using Api.Messages.Identity;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using WebApi.ViewModels;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly IAntiForgeryCookieService _antiForgery;
        private readonly ITokenStoreService _tokenStoreService;

        public AuthController(UserManager<User> userManager, IAntiForgeryCookieService antiForgery, ITokenStoreService tokenStoreService)
        {
            _userManager = userManager;
            _antiForgery = antiForgery;
            _tokenStoreService = tokenStoreService;
        }

        // POST api/auth/login
        [AllowAnonymous]
        [IgnoreAntiforgeryToken]
        [HttpPost("[action]")]
        public async Task<IActionResult> Login([FromBody]CredentialsViewModel credentials)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await GetUserIdentity(credentials.Email, credentials.Password);
            if (user == null)
            {
                return Unauthorized();
            }

            var (accessToken, refreshToken, claims) = await _tokenStoreService.CreateJwtTokens(user, refreshTokenSource: null);

            _antiForgery.RegenerateAntiForgeryCookies(claims);

            return Ok(new { access_token = accessToken, refresh_token = refreshToken });
        }

        [AllowAnonymous]
        [HttpPost("[action]")]
        public async Task<IActionResult> RefreshToken([FromBody]JToken jsonBody)
        {
            var refreshToken = jsonBody.Value<string>("refreshToken");
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return BadRequest("refreshToken is not set.");
            }

            var token = await _tokenStoreService.FindTokenAsync(refreshToken);
            if (token == null)
            {
                return Unauthorized();
            }

            var (accessToken, newRefreshToken, claims) = await _tokenStoreService.CreateJwtTokens(token.User, refreshToken);

            _antiForgery.RegenerateAntiForgeryCookies(claims);

            return Ok(new { access_token = accessToken, refresh_token = newRefreshToken });
        }


        private async Task<User> GetUserIdentity(string email, string password)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
                return await Task.FromResult<User>(null);

            // get the user to verifty
            var userToVerify = await _userManager.FindByNameAsync(email); //username and email is the same value

            if (userToVerify == null) return await Task.FromResult<User>(null);

            // check the credentials
            if (await _userManager.CheckPasswordAsync(userToVerify, password))
            {
                return await Task.FromResult(userToVerify);
            }

            // Credentials are invalid, or account doesn't exist
            return await Task.FromResult<User>(null);
        }

    }
}
