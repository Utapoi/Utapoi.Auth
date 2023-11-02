using System.Security.Claims;

namespace Utapoi.Auth.Extensions;

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    ///     Gets the email from the claims principal.
    /// </summary>
    /// <param name="principal">The claims principal.</param>
    /// <returns>
    ///     The email or <see langword="null" /> if not found.
    /// </returns>
    public static string? GetEmail(this ClaimsPrincipal principal)
    {
        return principal.FindFirstValue(ClaimTypes.Email);
    }

    /// <summary>
    ///     Gets the first value of the claim type from the claims principal.
    /// </summary>
    /// <typeparam name="T">The type to convert the value to.</typeparam>
    /// <param name="principal">The claims principal.</param>
    /// <param name="claimType">The claim type.</param>
    /// <returns>
    ///     The first value of the claim type or <see langword="null" /> if not found.
    /// </returns>
    public static T? FindFirstValue<T>(this ClaimsPrincipal principal, string claimType)
    {
        var v = principal.FindFirst(claimType)?.Value;

        return string.IsNullOrWhiteSpace(v) ? default : ConvertTo<T>(v);
    }

    private static T? ConvertTo<T>(string value)
    {
        return (T)Convert.ChangeType(value, typeof(T));
    }
}