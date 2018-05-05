using System.Threading;
using System.Threading.Tasks;
using Api.Messages.Identity;
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    public class ManageController : Controller
    {
        private readonly IRoleStore<Role> _roleStore;
        private readonly IMapper _mapper;

        public ManageController(IRoleStore<Role> roleStore, IMapper mapper)
        {
            _roleStore = roleStore;
            _mapper = mapper;
        }

        // POST api/manage
        [HttpPost]
        [IgnoreAntiforgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> Post([FromBody]string model) //Create user
        {
            var result = await _roleStore.CreateAsync(new Role()
            {
                Name = "User"
            }, new CancellationTokenSource().Token);

            if (result.Succeeded)
                return new CreatedResult("role", new { model });
            else
                return new BadRequestObjectResult(result.Errors);
        }
    }
}
