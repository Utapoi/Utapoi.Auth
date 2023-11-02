using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Auth.Commands.LogIn;

public static partial class LogIn
{
    public sealed class Command : IRequest<Result<Response>>
    {
        public string Username { get; set; } = string.Empty;

        public string Password { get; set; } = string.Empty;

        public string IpAddress { get; set; } = string.Empty;
    }
}