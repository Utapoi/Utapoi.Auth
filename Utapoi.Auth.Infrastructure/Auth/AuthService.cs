using FluentResults;
using Microsoft.AspNetCore.Identity;
using Utapoi.Auth.Application.Auth;
using Utapoi.Auth.Application.Auth.Commands.LogIn;
using Utapoi.Auth.Application.Auth.Commands.Register;
using Utapoi.Auth.Application.Tokens;
using Utapoi.Auth.Core.Entities;

namespace Utapoi.Auth.Infrastructure.Auth;

public sealed class AuthService : IAuthService
{
    private readonly UserManager<UtapoiUser> _userManager;

    private readonly SignInManager<UtapoiUser> _signInManager;

    private readonly IUserEmailStore<UtapoiUser> _emailStore;

    private readonly IUserStore<UtapoiUser> _userStore;

    private readonly ITokenService _tokenService;

    public AuthService(
        UserManager<UtapoiUser> userManager,
        SignInManager<UtapoiUser> signInManager,
        IUserEmailStore<UtapoiUser> emailStore,
        IUserStore<UtapoiUser> userStore,
        ITokenService tokenService
    )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _emailStore = emailStore;
        _userStore = userStore;
        _tokenService = tokenService;
    }

    public async Task<Result<LogIn.Response>> LogInAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default
    )
    {
        var user = await _userManager.FindByNameAsync(username);

        if (user == null)
        {
            return Result.Fail<LogIn.Response>("User does not exist.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);

        if (!result.Succeeded)
        {
            return Result.Fail<LogIn.Response>("Invalid password.");
        }

        return Result.Ok(new LogIn.Response
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            Username = user.UserName ?? user.Email ?? string.Empty,
        });
    }

    public async Task<Result<Register.Response>> RegisterAsync(
        string email,
        string password,
        string username,
        string ipAddress,
        CancellationToken cancellationToken = default
    )
    {
        if (await UserAlreadyExists(username, email))
        {
            return Result.Fail<Register.Response>("User already exists.");
        }

        var user = new UtapoiUser();

        await _userStore.SetUserNameAsync(user, username, cancellationToken);
        await _emailStore.SetEmailAsync(user, email, cancellationToken);

        var result = await _userManager.CreateAsync(user, password);

        if (!result.Succeeded)
        {
            return Result.Fail<Register.Response>(result.Errors.First().Description);
        }

        return Result.Ok(new Register.Response
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            Username = user.UserName ?? user.Email ?? string.Empty,
            Roles = Array.Empty<string>(), // TODO: Implement roles
        });
    }

    private async Task<bool> UserAlreadyExists(string username, string email)
    {
        var userByName = await _userManager.FindByNameAsync(username);
        var userByEmail = await _userManager.FindByEmailAsync(email);

        return userByName != null || userByEmail != null;
    }
}