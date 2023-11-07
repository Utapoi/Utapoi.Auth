using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace Utapoi.Auth.Core.Entities.Identity;

public class UtapoiUser : UtapoiUser<Guid>
{
}

public class UtapoiUser<TKey> : IdentityUser<TKey> where TKey : IEquatable<TKey>
{
    public ICollection<UtapoiClaim> Claims { get; set; } = new List<UtapoiClaim>();

    public ICollection<UtapoiRole> Roles { get; set; } = new List<UtapoiRole>();

    public ICollection<UtapoiUserLogin> Logins { get; set; } = new List<UtapoiUserLogin>();

    public ICollection<Token> Tokens { get; set; } = new List<Token>();

    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();

    public void AddClaim(Claim claim)
    {
        Claims.Add(new UtapoiClaim(claim));
    }

    public void AddClaim(UtapoiClaim claim)
    {
        Claims.Add(claim);
    }

    public void AddLogin(UserLoginInfo login)
    {
        Logins.Add(new UtapoiUserLogin(login));
    }

    public void AddRole(UtapoiRole role)
    {
        Roles.Add(role);
    }

    public void RemoveClaim(UtapoiClaim claim)
    {
        if (!Claims.Contains(claim))
            return;

        Claims.Remove(claim);
    }

    public void RemoveLogin(UtapoiUserLogin login)
    {
        if (!Logins.Contains(login))
            return;

        Logins.Remove(login);
    }

    public void RemoveLogin(UserLoginInfo login)
    {
        var l = new UtapoiUserLogin(login);

        if (!Logins.Contains(l))
            return;

        Logins.Remove(l);
    }

    public void RemoveRole(UtapoiRole role)
    {
        if (!Roles.Contains(role))
            return;

        Roles.Remove(role);
    }

    public void SetEmail(string? email)
    {
        Email = email;
    }

    public void SetEmailConfirmed(bool confirmed)
    {
        EmailConfirmed = confirmed;
    }

    public void SetLockoutEnabled(bool enabled)
    {
        LockoutEnabled = enabled;
    }

    public void SetLockoutEnd(DateTimeOffset? lockoutEnd)
    {
        LockoutEnd = lockoutEnd;
    }

    public void SetNormalizedEmail(string? normalizedEmail)
    {
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            NormalizedEmail = string.Empty;

            return;
        }

        NormalizedEmail = normalizedEmail.ToUpperInvariant().Trim();
    }

    public void SetNormalizedName(string? normalizedName)
    {
        if (string.IsNullOrWhiteSpace(normalizedName))
        {
            NormalizedUserName = string.Empty;

            return;
        }

        NormalizedUserName = normalizedName.ToUpperInvariant().Trim();
    }

    public void SetNormalizedUserName(string? normalizedUserName)
    {
        if (string.IsNullOrWhiteSpace(normalizedUserName))
        {
            NormalizedUserName = string.Empty;

            return;
        }

        NormalizedUserName = normalizedUserName.ToUpperInvariant().Trim();
    }

    public void SetPasswordHash(string? passwordHash)
    {
        PasswordHash = passwordHash;
    }

    public void SetSecurityStamp(string securityStamp)
    {
        SecurityStamp = securityStamp;
    }

    public void SetTwoFactorEnabled(bool enabled)
    {
        TwoFactorEnabled = enabled;
    }

    public void SetUserName(string? userName)
    {
        UserName = userName;
    }
}