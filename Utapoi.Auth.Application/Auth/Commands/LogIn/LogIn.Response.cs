namespace Utapoi.Auth.Application.Auth.Commands.LogIn;

public static partial class LogIn
{
    public sealed class Response
    {
        public Guid Id { get; set; }

        public string Email { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public string Token { get; set; } = string.Empty;

        public string RefreshToken { get; set; } = string.Empty;

        public DateTime TokenExpiration { get; set; }

        public DateTime RefreshTokenExpiration { get; set; }

        public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    }
}