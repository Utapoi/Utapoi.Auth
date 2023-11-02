using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Utapoi.Auth.Infrastructure.Options.JWT;

public class ConfigureJwtBearerOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly JwtOptions _jwtSettings;

    public ConfigureJwtBearerOptions(IOptions<JwtOptions> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public void Configure(JwtBearerOptions options)
    {
        Configure(string.Empty, options);
    }

    public void Configure(string? name, JwtBearerOptions options)
    {
        if (name != JwtBearerDefaults.AuthenticationScheme)
        {
            return;
        }

        var key = SHA512.HashData(Encoding.UTF8.GetBytes(_jwtSettings.Key));

        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidateLifetime = true,
            ValidateAudience = true,
            ValidIssuer = _jwtSettings.ValidIssuer,
            ValidAudience = _jwtSettings.ValidAudience,
            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.Zero
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                if (!context.Request.Cookies.TryGetValue("Utapoi-Token", out var uToken))
                {
                    return Task.CompletedTask;
                }

                if (string.IsNullOrWhiteSpace(uToken))
                {
                    return Task.CompletedTask;
                }

                context.Token = uToken;

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("X-Token-Expired", "true");
                    context.Response.StatusCode = 401;
                }
                else
                {
                    // Note(Mikyan): We assume that the user does not have access to the resource.
                    // Maybe this will change in the future.
                    context.Response.StatusCode = 403;
                }

                return Task.CompletedTask;
            }
        };
    }
}