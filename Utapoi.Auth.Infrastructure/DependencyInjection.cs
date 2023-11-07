using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Utapoi.Auth.Application.Auth;
using Utapoi.Auth.Application.Identity;
using Utapoi.Auth.Application.Tokens;
using Utapoi.Auth.Core.Entities.Identity;
using Utapoi.Auth.Infrastructure.Auth;
using Utapoi.Auth.Infrastructure.Identity;
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
        services.AddScoped<IUsersService, UsersService>();
        services.AddScoped<IUserEmailStore<UtapoiUser>, UserStore<UtapoiUser, UtapoiRole, UtapoiDbContext, Guid>>();

        services.AddOptions<JwtOptions>()
            .BindConfiguration($"{nameof(JwtOptions)}")
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddAntiforgery();

        services
            .AddDbContext<UtapoiDbContext>(c =>
            {
                c.UseMongoDB(configuration.GetConnectionString("UtapoiAuthDb")!, "UtapoiAuthDb");
            });

        services
            .AddIdentityCore<UtapoiUser>(c =>
            {

                c.SignIn.RequireConfirmedAccount = false;
                c.SignIn.RequireConfirmedEmail = false;

                c.User.RequireUniqueEmail = true;
                c.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            })
            .AddRoles<UtapoiRole>()
            .AddEntityFrameworkStores<UtapoiDbContext>()
            .AddDefaultTokenProviders()
            .AddUserStore<UtapoiUserStore<UtapoiUser, UtapoiRole, UtapoiDbContext, Guid>>()
            .AddRoleManager<RoleManager<UtapoiRole>>()
            .AddRoleStore<RoleStore<UtapoiRole, UtapoiDbContext, Guid>>()
            .AddSignInManager();

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddScheme<JwtBearerOptions, UtapoiJwtBearerHandler>(JwtBearerDefaults.AuthenticationScheme, _ => { });

        services.AddAuthorization();

        return services;
    }
}