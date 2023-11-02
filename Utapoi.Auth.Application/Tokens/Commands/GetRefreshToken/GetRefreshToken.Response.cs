namespace Utapoi.Auth.Application.Tokens.Commands.GetRefreshToken;

public static partial class GetRefreshToken
{
    public sealed class Response
    {
        public string Token { get; init; } = string.Empty;

        public string RefreshToken { get; init; } = string.Empty;

        public DateTime TokenExpiryTime { get; init; }

        public DateTime RefreshTokenExpiryTime { get; init; }
    }
}