using Microsoft.AspNetCore.Identity;

namespace Utapoi.Auth.Core.Entities;

public class UtapoiUser : IdentityUser<Guid>
{
    public ICollection<Token> Tokens { get; set; } = new List<Token>();

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}