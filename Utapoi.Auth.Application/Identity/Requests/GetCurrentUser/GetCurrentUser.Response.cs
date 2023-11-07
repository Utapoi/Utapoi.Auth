using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Application.Identity.Requests.GetCurrentUser;

public static partial class GetCurrentUser
{
    public sealed class Response
    {
        public Guid Id { get; set; } = default!;

        public string Username { get; set; } = string.Empty;

        public List<string> Roles { get; set; } = new();
    }
}