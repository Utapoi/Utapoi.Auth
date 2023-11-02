using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Auth.Commands.Register;

public static partial class Register
{
    public sealed class Command : IRequest<Result<Response>>
    {
        public string Email { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public string IpAddress { get; set; } = string.Empty;
    }
}