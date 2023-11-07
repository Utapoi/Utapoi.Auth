using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;
using Utapoi.Auth.Application.Tokens;

namespace Utapoi.Auth.Infrastructure.Tokens;

public sealed class UtapoiJwtBearerHandler : JwtBearerHandler
{
    private readonly ITokenService _tokenService;
    public UtapoiJwtBearerHandler(
        IOptionsMonitor<JwtBearerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ITokenService tokenService) : base(options, logger, encoder, clock)
    {
        _tokenService = tokenService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Context.Request.Cookies.TryGetValue("Utapoi-Token", out var uToken))
        {
            return Task.FromResult(AuthenticateResult.Fail("Authorization header not found."));
        }

        var result = _tokenService.Validate(uToken);

        if (result.IsFailed)
        {
            return Task.FromResult(AuthenticateResult.Fail("Token validation failed"));
        }

        var claims = GetClaims(uToken);

        if (claims == null)
        {
            return Task.FromResult(AuthenticateResult.Fail("Token validation failed"));
        }

        Context.User = new ClaimsPrincipal(claims);

        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claims, "Utapoi-Token")));
    }

    private static ClaimsPrincipal? GetClaims(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        if (handler.ReadToken(token) is not JwtSecurityToken tokenResult)
        {
            return null;
        }

        var claimsIdentity = new ClaimsIdentity(tokenResult.Claims, "Token");
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        return claimsPrincipal;
    }
}