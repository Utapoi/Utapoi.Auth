using FluentResults;
using MediatR;

namespace Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;

public static partial class GetRefreshToken
{
    public sealed class Command : IRequest<Result<Response>>
    {
        public string Token { get; init; } = string.Empty;

        public string RefreshToken { get; init; } = string.Empty;

        public string IpAddress { get; init; } = string.Empty;
    }
}