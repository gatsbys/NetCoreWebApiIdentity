using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Api.Identity;
using Api.Messages.Identity;
using Api.Services.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;

namespace Api.Services.Implementations
{
    public class TokenValidatorService : ITokenValidatorService
    {
        private readonly IUserStore<User> _usersStoreService;
        private readonly ILastLoggedIn _lastLoggedIn;
        private readonly ITokenStoreService _tokenStoreService;

        public TokenValidatorService(IUserStore<User> usersStoreService, ITokenStoreService tokenStoreService, ILastLoggedIn lastLoggedIn)
        {
            _usersStoreService = usersStoreService;
            _usersStoreService.CheckArgumentIsNull(nameof(usersStoreService));

            _tokenStoreService = tokenStoreService;
            _lastLoggedIn = lastLoggedIn;
            _tokenStoreService.CheckArgumentIsNull(nameof(_tokenStoreService));
        }

        public async Task ValidateAsync(TokenValidatedContext context)
        {
            var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
            if (claimsIdentity?.Claims == null || !claimsIdentity.Claims.Any())
            {
                context.Fail("This is not our issued token. It has no claims.");
                return;
            }

            var serialNumberClaim = claimsIdentity.FindFirst(ClaimTypes.SerialNumber);
            if (serialNumberClaim == null)
            {
                context.Fail("This is not our issued token. It has no serial.");
                return;
            }

            var userIdString = claimsIdentity.FindFirst(ClaimTypes.UserData).Value;

            var cancellationTokenSource = new CancellationTokenSource();
            var user = await _usersStoreService.FindByIdAsync(userIdString, cancellationTokenSource.Token);

            if (user == null || user.SecurityStamp != serialNumberClaim.Value)
            {
                // user has changed his/her password/roles/stat/IsActive
                context.Fail("This token is expired. Please login again.");
            }

            var accessToken = context.SecurityToken as JwtSecurityToken;
            if (accessToken == null || string.IsNullOrWhiteSpace(accessToken.RawData) ||
                !await _tokenStoreService.IsValidTokenAsync(accessToken.RawData, userIdString))
            {
                context.Fail("This token is not in our database.");
                return;
            }
            await _lastLoggedIn.UpdateUserLastActivityDateAsync(userIdString, cancellationTokenSource.Token);
        }
    }
}
