using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Utapoi.Auth.Application.Common.Errors;
using Utapoi.Auth.Application.Identity.Requests.GetCurrentUser;
using Utapoi.Auth.Attributes;

namespace Utapoi.Auth.Controllers;

public sealed class UsersController : ApiControllerBase
{
    [HttpGet("Me")]
    [Authorize]
    [ProducesResponseType(typeof(GetCurrentUser.Response), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetCurrentUserAsync()
    {
        var result = await Mediator.Send(new GetCurrentUser.Request
        {
            UserId = GetCurrentUserId()
        });

        if (result.IsFailed && result.HasError<EntityNotFoundError>())
        {
            return NotFound();
        }

        if (result.IsFailed)
        {
            return BadRequest(result.Errors.First().Message);
        }

        return Ok(result.Value);
    }
}