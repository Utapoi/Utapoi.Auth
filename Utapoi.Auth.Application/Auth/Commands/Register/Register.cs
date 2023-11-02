using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Auth.Commands.Register;

public static partial class Register
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
            return _authService.RegisterAsync(
                request.Email,
                request.Password,
                request.Username,
                request.IpAddress,
                cancellationToken
            );
        }
    }
}