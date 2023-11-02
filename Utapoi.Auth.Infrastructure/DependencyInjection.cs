using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Utapoi.Auth.Application.Auth;
using Utapoi.Auth.Application.Tokens;
using Utapoi.Auth.Core.Entities;
using Utapoi.Auth.Infrastructure.Auth;
using Utapoi.Auth.Infrastructure.Options.JWT;
using Utapoi.Auth.Infrastructure.Persistence;
using Utapoi.Auth.Infrastructure.Tokens;

namespace Utapoi.Auth.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<ITokenService, TokenService>();
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IUserEmailStore<UtapoiUser>, UserStore<UtapoiUser, IdentityRole<Guid>, UtapoiAuthDbContext, Guid>>();

        services.AddOptions<JwtOptions>()
            .BindConfiguration($"{nameof(JwtOptions)}")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services
            .AddDbContext<UtapoiAuthDbContext>(c =>
            {
                c.UseMongoDB(configuration.GetConnectionString("UtapoiAuthDb")!, "UtapoiAuthDb");
            });

        services
            .AddIdentity<UtapoiUser, IdentityRole<Guid>>(c =>
            {
                c.SignIn.RequireConfirmedAccount = false;
                c.SignIn.RequireConfirmedEmail = false;

                c.User.RequireUniqueEmail = true;
                c.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            })
            .AddEntityFrameworkStores<UtapoiAuthDbContext>()
            .AddDefaultTokenProviders()
            .AddUserStore<UserStore<UtapoiUser, IdentityRole<Guid>, UtapoiAuthDbContext, Guid>>()
            .AddSignInManager();

        services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(c =>
            {
                c.Cookie.Name = "UtapoiAuth";
                c.Cookie.Domain = ".utapoi.com";
                c.Cookie.HttpOnly = true;
                c.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                c.Cookie.SameSite = SameSiteMode.Strict;

                c.ExpireTimeSpan = TimeSpan.FromHours(2);
                c.SlidingExpiration = true;
            });

        services.AddAuthorization();

        return services;
    }
}