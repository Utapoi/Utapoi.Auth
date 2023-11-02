using FluentResults;
using Utapoi.Auth.Application.Auth.Commands.LogIn;
using Utapoi.Auth.Application.Auth.Commands.Register;

namespace Utapoi.Auth.Application.Auth;

public interface IAuthService
{
    Task<Result<LogIn.Response>> LogInAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default
    );

    Task<Result<Register.Response>> RegisterAsync(
        string email,
        string password,
        string username,
        string ipAddress,
        CancellationToken cancellationToken = default
    );
}