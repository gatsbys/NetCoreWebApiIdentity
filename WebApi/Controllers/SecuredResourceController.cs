using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApi.Controllers
{
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
        [Authorize(Policy = CustomRoles.Admin)]
        public class SecuredResourceController : Controller
        {
            // POST api/securedresource
            [HttpGet]
            public async Task<IActionResult> Get() //Create user
            {
                return Ok();
            }
        }
    }

}
