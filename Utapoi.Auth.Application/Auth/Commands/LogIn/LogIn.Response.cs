namespace Utapoi.Auth.Application.Auth.Commands.LogIn;

public static partial class LogIn
{
    public sealed class Response
    {
        public Guid Id { get; set; }

        public string Email { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;
    }
}