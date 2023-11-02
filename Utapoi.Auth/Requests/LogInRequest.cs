namespace Utapoi.Auth.Requests;

public sealed class LogInRequest
{
    public string Username { get; set; } = default!;

    public string Password { get; set; } = default!;
}