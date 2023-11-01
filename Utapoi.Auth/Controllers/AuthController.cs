using Microsoft.AspNetCore.Mvc;

namespace Utapoi.Auth.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAsync()
    {
        return Ok();
    }
}