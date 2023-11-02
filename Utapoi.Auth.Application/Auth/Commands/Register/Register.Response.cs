namespace Utapoi.Auth.Application.Auth.Commands.Register;

public static partial class Register
{
    public sealed class Response
    {
        public Guid Id { get; set; }

        public string Email { get; set; } = string.Empty;

        public string Username { get; set; } = string.Empty;

        public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    }
}