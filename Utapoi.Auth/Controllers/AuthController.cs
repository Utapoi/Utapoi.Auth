using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Utapoi.Auth.Application.Auth.Commands.LogIn;
using Utapoi.Auth.Application.Auth.Commands.Register;
using Utapoi.Auth.Requests;

namespace Utapoi.Auth.Controllers;

public class AuthController : ApiControllerBase
{
    [HttpPost("LogIn")]
    [ProducesResponseType(typeof(LogIn.Response), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> LoginAsync(
        [FromBody] LogInRequest req,
        CancellationToken cancellationToken
    )
    {
        var result = await Mediator.Send(new LogIn.Command
        {
            Username = req.Username,
            Password = req.Password,
            IpAddress = GetIpAddressFromRequest()
        }, cancellationToken);

        if (result.IsFailed)
        {
            return BadRequest(result.Errors.First().Message);
        }

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            CreateClaims(result.Value),
            new AuthenticationProperties
            {
                ExpiresUtc = DateTime.UtcNow.AddDays(1),
                IsPersistent = true,
                AllowRefresh = true,
                IssuedUtc = DateTime.UtcNow,
            }
        );

        // TODO: Redirect to the page from the query.
        return Ok(result.Value.Id);
    }

    [HttpPost("LogOut")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> LogOutAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Ok();
    }

    [HttpPost("Register")]
    [ProducesResponseType(typeof(Register.Response), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RegisterAsync(
        [FromBody] RegisterRequest req,
        CancellationToken cancellationToken
    )
    {
        var result = await Mediator.Send(new Register.Command
        {
            Email = req.Email,
            Password = req.Password,
            Username = req.Username,
            IpAddress = GetIpAddressFromRequest()
        }, cancellationToken);

        if (result.IsFailed)
        {
            return BadRequest(result.Errors.First().Message);
        }

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            CreateClaims(result.Value),
            new AuthenticationProperties
            {
                ExpiresUtc = DateTime.UtcNow.AddDays(1),
                IsPersistent = true,
                AllowRefresh = true,
                IssuedUtc = DateTime.UtcNow,
            }
        );

        // TODO: Redirect to the page from the query.
        return Ok(result.Value.Id);
    }

    private static ClaimsPrincipal CreateClaims(LogIn.Response response)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, response.Id.ToString()),
            new(ClaimTypes.Name, response.Username),
            new(ClaimTypes.Email, response.Email)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        return new ClaimsPrincipal(claimsIdentity);
    }

    private static ClaimsPrincipal CreateClaims(Register.Response response)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, response.Id.ToString()),
            new(ClaimTypes.Name, response.Username),
            new(ClaimTypes.Email, response.Email)
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        return new ClaimsPrincipal(claimsIdentity);
    }
}