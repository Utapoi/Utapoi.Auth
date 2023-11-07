﻿using System.Security.Claims;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Utapoi.Auth.Controllers;

[ApiController]
[Route("[controller]")]
public class ApiControllerBase : ControllerBase
{
    private ISender? _mediator;

    /// <summary>
    ///     Gets the mediator.
    /// </summary>
    protected ISender Mediator => _mediator ??= HttpContext.RequestServices.GetRequiredService<ISender>();

    /// <summary>
    ///     Gets the origin from the request.
    /// </summary>
    /// <returns>
    ///     The origin from the request.
    /// </returns>
    protected string GetOriginFromRequest()
    {
        return $"{Request.Scheme}://{Request.Host.Value}{Request.PathBase.Value}";
    }

    /// <summary>
    ///     Gets the IP address from the request.
    /// </summary>
    /// <returns>
    ///     The IP address from the request or an empty string if it cannot be found.
    /// </returns>
    protected string GetIpAddressFromRequest()
    {
        return Request.HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Gets the Id of the user that made the request.
    /// </summary>
    /// <returns>
    /// The Id of the user that made the request.
    /// </returns>
    protected Guid GetCurrentUserId()
    {
        var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);

        return string.IsNullOrWhiteSpace(userId)
            ? Guid.Empty
            : Guid.Parse(userId);
    }
}