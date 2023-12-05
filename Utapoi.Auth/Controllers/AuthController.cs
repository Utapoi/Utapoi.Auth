using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Utapoi.Auth.Application.Auth.Commands.LogIn;
using Utapoi.Auth.Application.Auth.Commands.Register;
using Utapoi.Auth.Attributes;
using Utapoi.Auth.Requests;

namespace Utapoi.Auth.Controllers;

public class AuthController : ApiControllerBase
{
    private readonly IAntiforgery _antiforgery;

    public AuthController(IAntiforgery antiforgery)
    {
        _antiforgery = antiforgery;
    }

    [HttpGet("Verify")]
    [UtapoiAuthorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ValidateAsync()
    {
        return Ok();
    }

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

        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);

        if (string.IsNullOrWhiteSpace(tokens.RequestToken))
        {
            return BadRequest("Failed to generate CSRF tokens.");
        }

        HttpContext.Response.Cookies.Append(
            "Utapoi-Token",
            result.Value.Token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                IsEssential = true,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            }
        );

        // TODO: Redirect to the page from the query.
        return Ok(result.Value.Id);
    }

    [HttpPost("LogOut")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> LogOutAsync()
    {
        HttpContext.Response.Cookies.Delete("Utapoi-Token");

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

        var tokens = _antiforgery.GetAndStoreTokens(HttpContext);

        if (string.IsNullOrWhiteSpace(tokens.RequestToken))
        {
            return BadRequest("Failed to generate CSRF tokens.");
        }

        HttpContext.Response.Cookies.Append(
            "Utapoi-Token",
            result.Value.Token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddDays(7)
            }
        );

        // TODO: Redirect to the page from the query.
        return Ok(result.Value.Id);
    }
}