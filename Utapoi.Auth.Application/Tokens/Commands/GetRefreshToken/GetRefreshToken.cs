using FluentResults;
using FluentValidation;
using JetBrains.Annotations;
using MediatR;

namespace Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;

// TODO: Rename this class to something more meaningful.
// We don't actually get a refresh token here because I don't know how to code, we get a new token.
// So maybe something like GetNewToken.Command / UpdateToken.Command / RegenerateToken.Command

public static partial class GetRefreshToken
{
    [UsedImplicitly]
    internal sealed class Handler : IRequestHandler<Command, Result<Response>>
    {
        private readonly ITokenService _tokenService;

        public Handler(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }

        public Task<Result<Response>> Handle(Command request, CancellationToken cancellationToken)
        {
            return _tokenService.GetRefreshTokenAsync(request, cancellationToken);
        }
    }
}