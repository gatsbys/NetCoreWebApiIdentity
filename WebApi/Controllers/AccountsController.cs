using System.Threading.Tasks;
using Api.Messages.Identity;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApi.ViewModels;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    public class AccountsController : Controller
    {
        private readonly UserManager<User> _userManager;
        private readonly IMapper _mapper;

        public AccountsController(UserManager<User> userManager, IMapper mapper)
        {
            _userManager = userManager;
            _mapper = mapper;
        }

        // POST api/accounts
        [HttpPost]
        [IgnoreAntiforgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Post([FromBody]RegistrationViewModel model) //Create user
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userIdentity = _mapper.Map<User>(model);

            var result = await _userManager.CreateAsync(userIdentity, model.Password);
            if(!result.Succeeded) return new BadRequestObjectResult(result.Errors);

            var roleResult = await _userManager.AddToRoleAsync(userIdentity, "Admin");

            if (!roleResult.Succeeded) return new BadRequestObjectResult(roleResult.Errors);

            return new CreatedResult("users", new { model.UserName });
        }
    }
}
