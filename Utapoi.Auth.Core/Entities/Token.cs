using Utapoi.Auth.Core.Entities.Common;
using Utapoi.Auth.Core.Entities.Identity;

namespace Utapoi.Auth.Core.Entities;

public class Token : AuditableEntity
{
    public string AccessToken { get; set; } = string.Empty;

    public string IpAddress { get; set; } = string.Empty;

    public Guid? RefreshTokenId { get; set; }

    public RefreshToken? RefreshToken { get; set; }

    public int UsageCount { get; set; } = 0;

    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow;

    public Guid? UserId { get; set; }

    public UtapoiUser? User { get; set; }

    public int ExpiresIn => (int)ExpiresAt.Subtract(DateTime.UtcNow).TotalSeconds;

    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
}