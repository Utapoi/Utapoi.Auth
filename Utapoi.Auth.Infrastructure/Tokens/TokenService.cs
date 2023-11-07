using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FluentResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Utapoi.Auth.Application.Common.Exceptions;
using Utapoi.Auth.Application.Tokens;
using Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;
using Utapoi.Auth.Application.Tokens.Commands.GetToken;
using Utapoi.Auth.Core.Entities;
using Utapoi.Auth.Core.Entities.Identity;
using Utapoi.Auth.Infrastructure.Extensions;
using Utapoi.Auth.Infrastructure.Options.JWT;
using Utapoi.Auth.Infrastructure.Persistence;

namespace Utapoi.Auth.Infrastructure.Tokens;

public struct TokenResponse
{
    public string Token { get; set; }

    public string RefreshToken { get; set; }

    public DateTime TokenExpiryTime { get; set; }

    public DateTime RefreshTokenExpiryTime { get; set; }
}

public class TokenService : ITokenService
{
    private readonly UtapoiDbContext _context;

    private readonly JwtOptions _jwtOptions;

    private readonly UserManager<UtapoiUser> _userManager;

    /// <summary>
    ///     Initializes a new instance of the <see cref="TokenService" /> class.
    /// </summary>
    /// <param name="userManager">The <see cref="UserManager{TUser}" />.</param>
    /// <param name="jwtOptions">The <see cref="JwtOptions" />.</param>
    /// <param name="context">The <see cref="UtapoiDbContext" />.</param>
    public TokenService(
        UserManager<UtapoiUser> userManager,
        IOptions<JwtOptions> jwtOptions,
        UtapoiDbContext context
    )
    {
        _userManager = userManager;
        _context = context;
        _jwtOptions = jwtOptions.Value;
    }

    public Result Validate(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(SHA512.HashData(Encoding.UTF8.GetBytes(_jwtOptions.Key))),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = _jwtOptions.ValidAudience,
            ValidIssuer = _jwtOptions.ValidIssuer,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero,
            ValidateLifetime = false
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(
                SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
        {
            return Result.Fail("Token Validation failed.");
        }

        return principal != null
            ? Result.Ok()
            : Result.Fail("Token Validation failed.");
    }

    public async Task<Result<GetToken.Response>> GetTokenAsync(
        string username,
        string ipAddress,
        CancellationToken cancellationToken = default
    )
    {
        var user = await _userManager.FindByNameAsync(username);

        if (user == null)
        {
            return Result.Fail("User not found");
        }

        if (TryGetValidTokenForUser(user, ipAddress, out var token) &&
            TryGetValidRefreshTokenForUser(user, ipAddress, out var refreshToken))
        {
            return Result.Ok(new GetToken.Response
            {
                Token = token.AccessToken,
                RefreshToken = refreshToken!.Token,
                TokenExpiryTime = token.ExpiresAt,
                RefreshTokenExpiryTime = refreshToken!.ExpiresAt
            });
        }

        var t = await GenerateTokensAndUpdateUser(user, ipAddress);

        return Result.Ok(new GetToken.Response
        {
            Token = t.Token,
            RefreshToken = t.RefreshToken,
            TokenExpiryTime = t.TokenExpiryTime,
            RefreshTokenExpiryTime = t.RefreshTokenExpiryTime
        });
    }

    /// <inheritdoc cref="ITokenService.GetRefreshTokenAsync(GetRefreshToken.Command, CancellationToken)" />
    public async Task<Result<GetRefreshToken.Response>> GetRefreshTokenAsync(
        GetRefreshToken.Command command,
        CancellationToken cancellationToken = default
    )
    {
        var userPrincipal = GetPrincipalFromExpiredToken(command.Token);
        var userEmail = userPrincipal.GetEmail();
        var user = await _context.Users
            .Include(x => x.Tokens)
            .Include(x => x.RefreshTokens)
            .ThenInclude(r => r.AccessToken)
            .FirstOrDefaultAsync(
                x => x.Email == userEmail
                     || x.NormalizedEmail == userEmail,
            cancellationToken);

        if (user is null)
        {
            return Result.Fail("User not found");
        }

        var refreshToken = user.RefreshTokens
            .SingleOrDefault(
                x => x.Token == command.RefreshToken
                     && x.IpAddress == command.IpAddress
            );

        var token = user.Tokens
            .SingleOrDefault(
                x => x.AccessToken == command.Token
                     && x.IpAddress == command.IpAddress
            );

        if (refreshToken is null || token is null)
        {
            return Result.Fail("Invalid token");
        }

        if (refreshToken.AccessToken.AccessToken != token.AccessToken)
        {
            // Be sure that the refresh token and the access token are related.
            // If they are not, we delete them both.
            await RemoveTokens(token, refreshToken, user);

            return Result.Fail("Invalid token");
        }

        if (refreshToken.IsExpired)
        {
            // If the refresh token is expired, we should delete it and the associated access token.
            await RemoveTokens(token, refreshToken, user);

            return Result.Fail("Refresh token has expired");
        }

        if (!refreshToken.IsValid)
        {
            // If the refresh token is invalid, we should delete it and the associated access token.
            // This could be because the user has his credentials stolen.
            // We should also delete all tokens that were created after this one.
            await RemoveTokens(token, refreshToken, user);

            return Result.Fail("Refresh token is invalid");
        }

        // At this point, the refresh token should be valid.
        // We can remove the old tokens and generate a new one.
        await RemoveTokens(token, refreshToken, user);

        var t = await GenerateTokensAndUpdateUser(user, command.IpAddress);

        return Result.Ok(new GetRefreshToken.Response
        {
            Token = t.Token,
            RefreshToken = t.RefreshToken,
            TokenExpiryTime = t.TokenExpiryTime,
            RefreshTokenExpiryTime = t.RefreshTokenExpiryTime
        });
    }

    private bool TryGetValidTokenForUser(
        UtapoiUser user,
        string ipAddress,
        [MaybeNullWhen(false)] out Token token
    )
    {
        token = _context.Tokens
            .FirstOrDefault(
                x => x.UserId.Equals(user.Id)
                     && x.IpAddress.Equals(ipAddress)
                     && x.ExpiresAt >= DateTime.UtcNow
            );

        return token != null;
    }

    private bool TryGetValidRefreshTokenForUser(
        UtapoiUser user,
        string ipAddress,
        [MaybeNullWhen(false)] out RefreshToken refreshToken
    )
    {
        refreshToken = _context.RefreshTokens
            .FirstOrDefault(
                x => x.UserId.Equals(user.Id)
                     && x.IpAddress.Equals(ipAddress)
                     && x.ExpiresAt >= DateTime.UtcNow
                     && x.UsageCount.Equals(0)
            );

        return refreshToken != null;
    }

    private async Task<TokenResponse> GenerateTokensAndUpdateUser(UtapoiUser user, string ipAddress)
    {
        var token = _context.Tokens.Add(new Token
        {
            AccessToken = await GenerateJwt(user),
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtOptions.TokenExpirationInMinutes),
            IpAddress = ipAddress,
            User = user,
            UserId = user.Id
        }).Entity;

        var refreshToken = _context.RefreshTokens.Add(new RefreshToken
        {
            AccessToken = token,
            Token = GenerateRefreshToken(),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenExpirationInDays),
            IpAddress = ipAddress,
            User = user,
            UserId = user.Id
        }).Entity;

        await _context.SaveChangesAsync();

        user.Tokens.Add(token);
        user.RefreshTokens.Add(refreshToken);

        return new TokenResponse
        {
            Token = token.AccessToken,
            RefreshToken = refreshToken.Token,
            TokenExpiryTime = token.ExpiresAt,
            RefreshTokenExpiryTime = refreshToken.ExpiresAt
        };
    }

    private async Task<string> GenerateJwt(UtapoiUser user)
    {
        return GenerateEncryptedToken(GetSigningCredentials(), await GetClaims(user));
    }

    private async Task<IEnumerable<Claim>> GetClaims(UtapoiUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email!),
            new(ClaimTypes.Name, user.UserName ?? string.Empty)
        };

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        return claims;
    }

    private static string GenerateRefreshToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var randomNumber = new byte[32];

        rng.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }

    private string GenerateEncryptedToken(SigningCredentials signingCredentials, IEnumerable<Claim> claims)
    {
        var token = new JwtSecurityToken(
            claims: claims,
            issuer: _jwtOptions.ValidIssuer,
            audience: _jwtOptions.ValidAudience,
            expires: DateTime.UtcNow.AddMinutes(_jwtOptions.TokenExpirationInMinutes),
            signingCredentials: signingCredentials);

        var tokenHandler = new JwtSecurityTokenHandler();

        return tokenHandler.WriteToken(token);
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(SHA512.HashData(Encoding.UTF8.GetBytes(_jwtOptions.Key))),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = _jwtOptions.ValidAudience,
            ValidIssuer = _jwtOptions.ValidIssuer,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero,
            ValidateLifetime = false
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(
                SecurityAlgorithms.HmacSha256,
                StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ForbiddenAccessException();
        }

        return principal;
    }

    private SigningCredentials GetSigningCredentials()
    {
        var key = SHA512.HashData(Encoding.UTF8.GetBytes(_jwtOptions.Key));

        return new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
    }

    private async Task RemoveTokens(Token token, RefreshToken refreshToken, UtapoiUser user)
    {
        user.RefreshTokens.Remove(refreshToken);
        user.Tokens.Remove(token);

        await _context.SaveChangesAsync();
    }
}