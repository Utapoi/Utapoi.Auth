using Microsoft.AspNetCore.Mvc.Filters;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Utapoi.Auth.Application.Tokens;

namespace Utapoi.Auth.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class UtapoiAuthorize : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext Context)
    {
        if (!Context.HttpContext.Request.Cookies.TryGetValue("Utapoi-Token", out var uToken))
        {
            Context.Result = new UnauthorizedResult();
            return;
        }

        var result = Context.HttpContext.RequestServices.GetRequiredService<ITokenService>().Validate(uToken);

        if (result.IsFailed)
        {
            Context.Result = new UnauthorizedResult();
            return;
        }

        var claims = GetClaims(uToken);

        if (claims == null)
        {
            Context.Result = new UnauthorizedResult();
            return;
        }

        Context.HttpContext.User = new ClaimsPrincipal(claims);
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