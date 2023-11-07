using System.Security.Claims;
using Utapoi.Auth.Core.Entities.Common;

namespace Utapoi.Auth.Core.Entities.Identity;

public class UtapoiClaim : Entity
{
    public UtapoiClaim()
    {
    }

    public UtapoiClaim(string type, string value)
    {
        Type = type;
        Value = value;
    }

    public UtapoiClaim(Claim claim)
    {
        Type = claim.Type;
        Value = claim.Value;
        Issuer = claim.Issuer;
    }

    /// <summary>
    /// The type of the claim.
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// The value of the claim.
    /// </summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>
    /// The issuer of the claim.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;


}