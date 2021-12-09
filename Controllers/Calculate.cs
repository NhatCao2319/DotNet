using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AccountManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Calculate : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> APlusB([FromForm]int A,[FromForm] int B)
        {
            var C = A + B;
            return Ok(C);
        }
    }
}
