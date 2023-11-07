using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Auth.Commands.LogIn;

public static partial class LogIn
{
    internal sealed class Handler : IRequestHandler<Command, Result<Response>>
    {
        private readonly IAuthService _authService;

        public Handler(IAuthService authService)
        {
            _authService = authService;
        }

        public Task<Result<Response>> Handle(Command request, CancellationToken cancellationToken)
        {
            return _authService.LogInAsync(
                request.Username,
                request.Password,
                request.IpAddress,
                cancellationToken
            );
        }
    }
}