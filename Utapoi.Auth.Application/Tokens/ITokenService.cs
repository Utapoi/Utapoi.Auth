using FluentResults;
using Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;
using Utapoi.Auth.Application.Tokens.Commands.GetToken;

namespace Utapoi.Auth.Application.Tokens;


/// <summary>
///     The token service.
/// </summary>
public interface ITokenService
{
    Result Validate(string token);

    /// <summary>
    ///     Gets the token for the specified username.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="ipAddress">The ip address of the user.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    ///     A <see cref="Result" /> containing the token response.
    /// </returns>
    Task<Result<GetToken.Response>> GetTokenAsync(
        string username,
        string ipAddress,
        CancellationToken cancellationToken = default
    );

    // TODO: Also rename this method in accordance with the new name of the command.

    /// <summary>
    ///     Gets a new token for the user.
    /// </summary>
    /// <param name="request">The request for obtaining a new token.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    ///     A <see cref="Result" /> containing the token response.
    /// </returns>
    Task<Result<GetRefreshToken.Response>> GetRefreshTokenAsync(
        GetRefreshToken.Command request,
        CancellationToken cancellationToken = default
    );
}